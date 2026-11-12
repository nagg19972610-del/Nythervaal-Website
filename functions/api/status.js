export const STALE_THRESHOLD_SECONDS = 60;
export const MAX_DRIFT_MS = 30_000;
export const NONCE_TTL_SECONDS = 60;
export const STATUS_KEY = 'server_status';
const MAX_BODY_BYTES = 2048;
const STATUS_PATH = '/api/status';
const REPORT_PATH = '/api/status/report';

const RESPONSE_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Nyther-Timestamp, X-Nyther-Nonce, X-Nyther-Signature',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...RESPONSE_HEADERS,
      'Content-Type': 'application/json; charset=utf-8',
      ...extraHeaders,
    },
  });
}

function unknownStatus(configured = false, extra = {}) {
  return jsonResponse({
    configured, status: 'unknown', online: null, players: null, updatedAt: null, ...extra,
  });
}

function isStatusRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (value.status === 'online' || value.status === 'offline') &&
    (value.players === null || (Number.isSafeInteger(value.players) && value.players >= 0)) &&
    Number.isSafeInteger(value.timestamp) && value.timestamp > 0 &&
    value.timestamp <= 8_640_000_000_000_000 &&
    (value.realmId === undefined || (Number.isInteger(value.realmId) && value.realmId >= 1 && value.realmId <= 0xffffffff)) &&
    (value.realmName === undefined || (typeof value.realmName === 'string' &&
      value.realmName.trim().length > 0 && value.realmName.length <= 128)) &&
    (value.version === undefined || value.version === 1) &&
    (value.online === undefined || value.online === (value.status === 'online'));
}

function parseJson(text) {
  if (typeof text !== 'string') return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function verifySignature(body, timestamp, nonce, signature, secret) {
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(signature.slice(index * 2, index * 2 + 2), 16);
  }
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    return await crypto.subtle.verify('HMAC', key, bytes, encoder.encode(`${timestamp}.${nonce}.${body}`));
  } catch {
    return false;
  }
}

async function readBody(request) {
  const length = request.headers.get('Content-Length');
  if (length !== null && /^\d+$/.test(length) && Number(length) > MAX_BODY_BYTES) {
    return { error: 'Payload too large', status: 413 };
  }

  if (!request.body) return { text: '' };
  let reader;
  const buffer = new Uint8Array(MAX_BODY_BYTES);
  let size = 0;
  try {
    reader = request.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > MAX_BODY_BYTES) {
        void reader.cancel().catch(() => {});
        return { error: 'Payload too large', status: 413 };
      }
      buffer.set(value, size);
      size += value.byteLength;
    }
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, size));
    return { text };
  } catch {
    return { error: 'Invalid request body', status: 400 };
  } finally {
    reader?.releaseLock();
  }
}

async function getStatus(kv) {
  if (!kv) return unknownStatus();
  let raw;
  try {
    raw = await kv.get(STATUS_KEY);
  } catch {
    return unknownStatus();
  }
  const record = parseJson(raw);
  const now = Date.now();
  if (!isStatusRecord(record) || record.timestamp > now) return unknownStatus();

  const updatedAt = new Date(record.timestamp).toISOString();
  if (now - record.timestamp > STALE_THRESHOLD_SECONDS * 1000) {
    return unknownStatus(true, { updatedAt, stale: true });
  }

  return jsonResponse({
    configured: true,
    status: record.status,
    online: record.status === 'online',
    players: record.status === 'offline' ? 0 : record.players,
    updatedAt,
  });
}

async function reportStatus(request, env) {
  const { STATUS_KV: kv, MONITORING_SECRET: secret } = env;
  const unavailable = () => jsonResponse({ error: 'Service unavailable' }, 503);
  if (!kv || typeof secret !== 'string' || !secret) return unavailable();

  const timestampHeader = request.headers.get('X-Nyther-Timestamp') ?? '';
  const nonce = request.headers.get('X-Nyther-Nonce') ?? '';
  const signature = request.headers.get('X-Nyther-Signature') ?? '';
  if (timestampHeader.length !== 13 || !/^[1-9][0-9]{12}$/.test(timestampHeader) ||
      nonce.length !== 36 || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(nonce) ||
      signature.length !== 64 || !/^[0-9a-f]{64}$/i.test(signature)) {
    return jsonResponse({ error: 'Invalid authentication headers' }, 401);
  }

  const timestamp = Number(timestampHeader);
  if (Math.abs(Date.now() - timestamp) > MAX_DRIFT_MS) {
    return jsonResponse({ error: 'Timestamp outside allowed window' }, 401);
  }

  const body = await readBody(request);
  if (body.error) return jsonResponse({ error: body.error }, body.status);
  if (!await verifySignature(body.text, timestampHeader, nonce, signature, secret)) {
    return jsonResponse({ error: 'Invalid signature' }, 401);
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > MAX_DRIFT_MS) {
    return jsonResponse({ error: 'Timestamp outside allowed window' }, 401);
  }
  const payload = parseJson(body.text);
  if (!isStatusRecord(payload) || payload.timestamp !== timestamp) {
    return jsonResponse({ error: 'Malformed payload structure' }, 400);
  }

  const nonceKey = `nonce:${nonce}`;
  const record = {
    realmId: payload.realmId ?? 1,
    realmName: payload.realmName ?? 'Nythervaal',
    status: payload.status,
    players: payload.status === 'offline' ? 0 : payload.players,
    timestamp,
  };

  // KV checks are best effort across locations. Reserve the nonce before updating status.
  try {
    const existing = parseJson(await kv.get(STATUS_KEY));
    if (isStatusRecord(existing) && existing.timestamp <= now + MAX_DRIFT_MS && timestamp <= existing.timestamp) {
      return jsonResponse({ error: 'Stale or duplicate timestamp' }, 409);
    }
    if (await kv.get(nonceKey) !== null) {
      return jsonResponse({ error: 'Replay detected' }, 409);
    }

    await kv.put(nonceKey, '1', { expirationTtl: NONCE_TTL_SECONDS });
    await kv.put(STATUS_KEY, JSON.stringify(record));
  } catch {
    return unavailable();
  }

  return jsonResponse({ ok: true, storedAt: new Date(now).toISOString() });
}

export async function handleStatusRequest(request, env = {}) {
  const path = new URL(request.url).pathname.replace(/\/$/, '');
  if (path !== STATUS_PATH && path !== REPORT_PATH) {
    return jsonResponse({ error: 'Not found' }, 404);
  }

  const methods = path === STATUS_PATH ? 'GET, POST, OPTIONS' : 'POST, OPTIONS';
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: { ...RESPONSE_HEADERS, 'Access-Control-Allow-Methods': methods, Allow: methods },
    });
  }
  if (request.method === 'GET' && path === STATUS_PATH) return getStatus(env.STATUS_KV);
  if (request.method === 'POST') return reportStatus(request, env);
  return jsonResponse({ error: 'Method not allowed' }, 405, { Allow: methods });
}

export function onRequest({ request, env }) {
  return handleStatusRequest(request, env);
}

export { onRequest as onRequestGet, onRequest as onRequestPost, onRequest as onRequestOptions };

export default { fetch: handleStatusRequest };
