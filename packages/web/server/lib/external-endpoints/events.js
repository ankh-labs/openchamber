import http from 'node:http';
import https from 'node:https';

import { createSpaceEventSources } from '../spaces/space-events.js';
import { basicAuthHeader } from './client.js';

// #5080 — the event fan-in reuses spaces/space-events.js unchanged: the only
// difference from a space is the transport. `requestInside` opens an ordinary
// HTTP(S) request to the endpoint with its Basic auth, instead of the space's
// dispatcher channel. Reconnect, backoff, stall detection, cursor/gap reporting
// and the host-hub injection all stay the shared implementation.

export function requestEndpoint(endpoint, requestPath, headers = {}, timeoutMs = null) {
  const target = new URL(endpoint.url);
  const transport = target.protocol === 'https:' ? https : http;
  const prefix = target.pathname.replace(/\/+$/, '');
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  return new Promise((resolve, reject) => {
    const request = transport.request(
      {
        protocol: target.protocol,
        hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: `${prefix}${requestPath}`,
        method: 'GET',
        headers: {
          accept: 'text/event-stream',
          ...headers,
          authorization: basicAuthHeader(endpoint.auth),
        },
      },
      resolve
    );
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      request.setTimeout(timeoutMs, () => request.destroy(new Error(`no answer within ${timeoutMs}ms`)));
    }
    request.on('error', reject);
    request.end();
  });
}

export function createExternalRequestInside(registry) {
  return async (endpointId, { path, headers = {}, timeoutMs = null } = {}) => {
    const endpoint = (await registry.list()).find((entry) => entry.id === endpointId);
    if (!endpoint) {
      const error = new Error(`no endpoint named ${endpointId}`);
      error.code = 'external_endpoint_unknown';
      throw error;
    }
    return requestEndpoint(endpoint, path, headers, timeoutMs);
  };
}

/**
 * Owns one shared event-source set for all endpoints. `sync` starts a
 * connection for a new endpoint and stops one that was removed, exactly as the
 * spaces host follows its spaces; the hub injection is tagged with the
 * ENDPOINT id, which is what the client uses to re-read that endpoint only.
 */
export function createExternalEventManager({
  registry,
  index,
  hub,
  broadcastUiEvent = null,
  broadcastGlobalUiEvent = null,
  logger = console,
  now = Date.now,
  stallTimeoutMs,
}) {
  let sources = null;
  const ensure = async () => {
    const endpoints = await registry.list();
    if (!sources) {
      sources = createSpaceEventSources({
        requestInside: createExternalRequestInside(registry),
        index,
        hub,
        broadcastUiEvent,
        broadcastGlobalUiEvent,
        logger,
        now,
        stallTimeoutMs,
      });
    }
    sources.sync(endpoints.map((endpoint) => endpoint.id));
    return endpoints.map((endpoint) => endpoint.id);
  };
  return {
    ensure,
    has: (endpointId) => sources?.has(endpointId) ?? false,
    close: () => sources?.close(),
  };
}
