import { checkEndpointHealth } from './client.js';
import { publicEndpoint } from './registry.js';

// #5080 — the HTTP surface of the endpoint registry. Mounted with the other
// `/api/openchamber` routes, after the API auth gate. JSON bodies are the
// server's common middleware's job; this router does not assume form encoding
// (the defect PR #1448 shipped).

const statusFor = (code) => {
  if (code === 'external_endpoint_id_taken' || code === 'external_endpoint_url_taken') return 409;
  if (
    code === 'external_endpoint_invalid' ||
    code === 'external_endpoint_url_invalid' ||
    code === 'external_endpoint_url_credentials' ||
    code === 'external_endpoint_private_host' ||
    code === 'external_endpoint_unresolvable'
  ) {
    return 400;
  }
  return 500;
};

export function registerExternalEndpointRoutes(app, { getRegistry, getMerge, onRegistryChanged = null, logger = console } = {}) {
  const registryOf = () => getRegistry?.() ?? null;

  app.get('/api/openchamber/external-endpoints', async (_req, res) => {
    const registry = registryOf();
    if (!registry) return res.json({ endpoints: [] });
    try {
      const endpoints = await registry.listPublic();
      const merge = getMerge?.();
      return res.json({
        endpoints: endpoints.map((endpoint) => ({
          ...endpoint,
          state: merge?.stateOf(endpoint.id)?.state ?? 'unknown',
          sessions: merge?.stateOf(endpoint.id)?.records?.length ?? null,
        })),
      });
    } catch (error) {
      logger.error?.(`[external-endpoints] list failed: ${error.message}`);
      return res.status(500).json({ error: 'the endpoint registry could not be read', code: 'external_endpoints_unreadable' });
    }
  });

  app.post('/api/openchamber/external-endpoints', async (req, res) => {
    const registry = registryOf();
    if (!registry) return res.status(503).json({ error: 'the endpoint registry is not available', code: 'external_endpoints_unavailable' });
    try {
      const endpoint = await registry.add(req.body ?? {});
      getMerge?.()?.invalidate(endpoint.id);
      await onRegistryChanged?.();
      // A registration is not complete until the server answers; the health
      // result travels with the created record, and a failure is reported
      // without hiding the endpoint the operator just saved.
      const health = await checkEndpointHealth(endpoint);
      return res.status(201).json({ endpoint: publicEndpoint(endpoint), health });
    } catch (error) {
      if (error?.code?.startsWith?.('external_endpoint')) {
        return res.status(statusFor(error.code)).json({ error: error.message, code: error.code });
      }
      logger.error?.(`[external-endpoints] add failed: ${error?.message ?? error}`);
      return res.status(500).json({ error: 'the endpoint could not be saved', code: 'external_endpoint_save_failed' });
    }
  });

  app.post('/api/openchamber/external-endpoints/:id/check', async (req, res) => {
    const registry = registryOf();
    if (!registry) return res.status(503).json({ error: 'the endpoint registry is not available', code: 'external_endpoints_unavailable' });
    try {
      const endpoint = await registry.get(req.params.id);
      if (!endpoint) return res.status(404).json({ error: 'no such endpoint', code: 'external_endpoint_not_found' });
      const health = await checkEndpointHealth(endpoint);
      return res.json({ endpoint: publicEndpoint(endpoint), health });
    } catch (error) {
      logger.error?.(`[external-endpoints] check failed: ${error?.message ?? error}`);
      return res.status(500).json({ error: 'the endpoint could not be checked', code: 'external_endpoint_check_failed' });
    }
  });

  app.delete('/api/openchamber/external-endpoints/:id', async (req, res) => {
    const registry = registryOf();
    if (!registry) return res.status(503).json({ error: 'the endpoint registry is not available', code: 'external_endpoints_unavailable' });
    try {
      const removed = await registry.remove(req.params.id);
      if (!removed) return res.status(404).json({ error: 'no such endpoint', code: 'external_endpoint_not_found' });
      getMerge?.()?.invalidate(req.params.id);
      await onRegistryChanged?.();
      return res.json({ removed: true, id: req.params.id });
    } catch (error) {
      logger.error?.(`[external-endpoints] remove failed: ${error?.message ?? error}`);
      return res.status(500).json({ error: 'the endpoint could not be removed', code: 'external_endpoint_remove_failed' });
    }
  });
}
