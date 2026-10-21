import { OpenCode } from '@opencode/client';

// #5080 — the transport for an external endpoint. The endpoint is a server the
// operator already runs, reached over HTTP with Basic auth; there is no space,
// no dispatcher channel and no container. `@opencode/client` 2.1.2 is the only
// client used (not the retired @opencode-ai/sdk).

export const basicAuthHeader = ({ username, password }) =>
  `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;

export function createEndpointClient(endpoint, { OpenCodeClient = OpenCode } = {}) {
  return OpenCodeClient.make({
    baseUrl: endpoint.url,
    headers: { Authorization: basicAuthHeader(endpoint.auth) },
  });
}

/**
 * Health is the client's own `server.info()` call, not a guessed path. A server
 * that answers is healthy; a 401, a refused connection or a timeout is a
 * failure with its reason, never a silent "unhealthy" boolean.
 */
export async function checkEndpointHealth(endpoint, { timeoutMs = 8000, makeClient = createEndpointClient } = {}) {
  const started = Date.now();
  const client = makeClient(endpoint);
  let timer = null;
  try {
    await Promise.race([
      client.server.info(),
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`no answer within ${timeoutMs}ms`)), timeoutMs);
        timer.unref?.();
      }),
    ]);
    return { ok: true, latencyMs: Date.now() - started };
  } catch (error) {
    return { ok: false, latencyMs: Date.now() - started, error: error?.message ?? String(error) };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** The endpoint's session records, in the shape the shared session index reads. */
export async function listEndpointSessions(endpoint, { makeClient = createEndpointClient } = {}) {
  const client = makeClient(endpoint);
  const response = await client.session.list({});
  if (Array.isArray(response)) return response;
  if (Array.isArray(response?.data)) return response.data;
  return [];
}
