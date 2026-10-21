import { createSpaceSessionIndex, mergeSessionLists } from '../spaces/space-sessions.js';
import { listEndpointSessions } from './client.js';

// #5080 — the merge reuses the spaces session index in TRUSTED mode: the
// directory of an external session is the remote server's own path, so the
// container-root containment check cannot apply. The collision rules stay on:
// a session id the host already owns wins, and two endpoints cannot speak for
// the same id.

const DEFAULT_SESSION_TTL_MS = 10_000;

export function createExternalSessionMerge({
  registry,
  listSessions = listEndpointSessions,
  logger = console,
  ttlMs = DEFAULT_SESSION_TTL_MS,
  now = Date.now,
} = {}) {
  if (!registry) throw new Error('registry is required');
  const index = createSpaceSessionIndex({ logger, trusted: true });
  const fetchedAt = new Map();

  const readEndpoint = async (endpoint) => {
    try {
      const records = await listSessions(endpoint);
      index.acceptSpaceList(endpoint.id, records, { complete: true });
      logger.info?.(`[external-endpoints] ${endpoint.id}: ${records.length} session(s)`);
    } catch (error) {
      // A failure keeps the last known list, marked stale; a missing answer is
      // never a deletion.
      logger.warn?.(`[external-endpoints] the session list of ${endpoint.id} did not come: ${error?.code ?? error?.message ?? error}`);
      index.markUnreachable(endpoint.id);
    }
    fetchedAt.set(endpoint.id, now());
  };

  /**
   * Merge every registered endpoint's sessions into the host's answer. The
   * registry is read on every call, so adding or removing an endpoint takes
   * effect on the next list with no process restart.
   */
  const merge = async (hostPayload) => {
    // The host's ids are the collision rule: a session the host already lists
    // wins, and an endpoint record with the same id is dropped. Learn them
    // before any endpoint list is accepted.
    const hostRecords = Array.isArray(hostPayload)
      ? hostPayload
      : Array.isArray(hostPayload?.data)
        ? hostPayload.data
        : [];
    index.observeHostRecords(hostRecords);
    const endpoints = await registry.list();
    const liveIds = new Set(endpoints.map((endpoint) => endpoint.id));
    for (const entry of index.snapshot()) {
      if (!liveIds.has(entry.spaceId)) {
        index.forget(entry.spaceId);
        fetchedAt.delete(entry.spaceId);
      }
    }
    await Promise.all(
      endpoints.map(async (endpoint) => {
        const last = fetchedAt.get(endpoint.id);
        if (last !== undefined && now() - last < ttlMs) return;
        await readEndpoint(endpoint);
      })
    );
    const answers = new Map(index.snapshot().map((entry) => [entry.spaceId, entry]));
    return mergeSessionLists(
      hostPayload,
      endpoints.flatMap((endpoint) => {
        const answer = answers.get(endpoint.id);
        return answer
          ? [
              {
                ...answer,
                // The label is what the UI groups under; the project and the
                // directory are the ENDPOINT's, so no host project is claimed.
                name: endpoint.label,
                projectDirectory: null,
                directory: null,
              },
            ]
          : []
      })
    );
  };

  return {
    index,
    merge,
    /** Force the next merge to re-read one endpoint (after add/remove/check). */
    invalidate: (endpointId) => fetchedAt.delete(endpointId),
    /** What the routes report without waiting for a list. */
    stateOf: (endpointId) => index.snapshot().find((entry) => entry.spaceId === endpointId) ?? null,
  };
}
