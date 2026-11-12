import { handleStatusRequest } from '../status.js';

export function onRequest({ request, env }) {
  return handleStatusRequest(request, env);
}
