// Cloudflare Pages Function: safe public status endpoint.
// No database connections, secrets, or local-network access.
// Until a trusted server-side monitoring feed is configured,
// always return "unknown" rather than claiming online/offline.
export async function onRequestGet() {
  return new Response(JSON.stringify({
    configured: false,
    status: "unknown",
    online: null,
    players: null,
    updatedAt: null
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
