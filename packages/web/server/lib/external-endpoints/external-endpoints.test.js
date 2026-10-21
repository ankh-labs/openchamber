import { describe, expect, it } from 'vitest';

import {
  assertExternalEndpointAllowed,
  createExternalEndpointRegistry,
  isPrivateAddress,
} from './registry.js';
import { createExternalSessionMerge } from './sessions.js';
import { checkEndpointHealth } from './client.js';

const endpoint = (overrides = {}) => ({
  id: 'ankh-grep',
  label: 'ankh-grep',
  url: 'http://192.168.9.11:4096',
  auth: { type: 'basic', username: 'opencode', password: 'opencode' },
  ...overrides,
});

const lookupOf = (addresses) => async (host) => {
  const value = addresses[host];
  if (!value) {
    const error = new Error('not found');
    error.code = 'ENOTFOUND';
    throw error;
  }
  return value.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
};

function memoryFs() {
  const files = new Map();
  return {
    files,
    async readFile(filePath) {
      if (!files.has(filePath)) {
        const error = new Error('ENOENT');
        error.code = 'ENOENT';
        throw error;
      }
      return files.get(filePath);
    },
    async writeFile(filePath, body) {
      files.set(filePath, body);
    },
    async rename(from, to) {
      files.set(to, files.get(from));
      files.delete(from);
    },
  };
}

const registryOf = (entries) => ({ list: async () => entries.map(endpoint) });

const record = (id, directory) => ({ id, title: id, location: { directory } });

describe('#5080 external endpoint address policy', () => {
  it('refuses a private address unless the allowlist names its range', async () => {
    await expect(assertExternalEndpointAllowed({ url: 'http://192.168.9.11:4096', allowPrivateHosts: [] })).rejects.toMatchObject({
      code: 'external_endpoint_private_host',
    });
    await expect(
      assertExternalEndpointAllowed({ url: 'http://192.168.9.11:4096', allowPrivateHosts: ['192.168.9.0/24'] })
    ).resolves.toMatchObject({ hostname: '192.168.9.11' });
  });

  it('resolves a hostname and refuses when it lands in a private range', async () => {
    await expect(
      assertExternalEndpointAllowed({
        url: 'http://opencode.lan:4096',
        allowPrivateHosts: [],
        lookup: lookupOf({ 'opencode.lan': ['192.168.4.20'] }),
      })
    ).rejects.toMatchObject({ code: 'external_endpoint_private_host' });
  });

  it('allows a public host, and refuses loopback by default', async () => {
    await expect(
      assertExternalEndpointAllowed({
        url: 'https://opencode.example.com',
        allowPrivateHosts: [],
        lookup: lookupOf({ 'opencode.example.com': ['93.184.216.34'] }),
      })
    ).resolves.toMatchObject({ addresses: ['93.184.216.34'] });
    await expect(assertExternalEndpointAllowed({ url: 'http://127.0.0.1:4096', allowPrivateHosts: [] })).rejects.toMatchObject({
      code: 'external_endpoint_private_host',
    });
    expect(isPrivateAddress('::1')).toBe(true);
    expect(isPrivateAddress('2600:1700:b0a1:6ed::9:116')).toBe(false);
  });
});

describe('#5080 endpoint registry', () => {
  it('persists, lists publicly without the password, and removes', async () => {
    const fs = memoryFs();
    const registry = createExternalEndpointRegistry({
      filePath: '/data/external-endpoints.json',
      allowPrivateHosts: ['192.168.9.0/24'],
      lookup: lookupOf({}),
      ...fs,
    });
    const added = await registry.add(endpoint());
    expect(added.id).toBe('ankh-grep');
    const publicList = await registry.listPublic();
    expect(publicList).toEqual([
      {
        id: 'ankh-grep',
        label: 'ankh-grep',
        url: 'http://192.168.9.11:4096',
        auth: { type: 'basic', username: 'opencode' },
        hasPassword: true,
      },
    ]);
    const stored = JSON.parse(fs.files.get('/data/external-endpoints.json'));
    expect(stored.endpoints[0].auth.password).toBe('opencode');
    await expect(registry.add(endpoint())).rejects.toMatchObject({ code: 'external_endpoint_id_taken' });
    await expect(registry.add(endpoint({ id: 'other' }))).rejects.toMatchObject({ code: 'external_endpoint_url_taken' });
    await expect(registry.remove('ankh-grep')).resolves.toBe(true);
    await expect(registry.list()).resolves.toEqual([]);
  });

  it('refuses a private endpoint that the allowlist does not name', async () => {
    const registry = createExternalEndpointRegistry({
      filePath: '/data/external-endpoints.json',
      allowPrivateHosts: [],
      lookup: lookupOf({}),
      ...memoryFs(),
    });
    await expect(registry.add(endpoint())).rejects.toMatchObject({ code: 'external_endpoint_private_host' });
  });
});

describe('#5080 merged sessions', () => {
  it('merges every endpoint with the host list and names each endpoint', async () => {
    const merge = createExternalSessionMerge({
      registry: registryOf([endpoint(), endpoint({ id: 'ankh-flurry', label: 'ankh-flurry', url: 'http://192.168.9.12:4096' })]),
      listSessions: async (entry) => [record(`${entry.id}-session`, `/root/${entry.id}`)],
    });
    const merged = await merge.merge({ data: [record('host-session', '/home/me/app')], cursor: {} });
    expect(merged.data.map((entry) => entry.id)).toEqual(['host-session', 'ankh-grep-session', 'ankh-flurry-session']);
    expect(merged.spaces).toEqual([
      expect.objectContaining({ id: 'ankh-grep', name: 'ankh-grep', state: 'complete', sessions: 1 }),
      expect.objectContaining({ id: 'ankh-flurry', name: 'ankh-flurry', state: 'complete', sessions: 1 }),
    ]);
  });

  it('keeps the host id and drops a colliding endpoint record', async () => {
    const merge = createExternalSessionMerge({
      registry: registryOf([endpoint()]),
      listSessions: async () => [record('host-session', '/root/collision'), record('endpoint-session', '/root/real')],
    });
    const merged = await merge.merge({ data: [record('host-session', '/home/me/app')] });
    expect(merged.data.map((entry) => entry.id)).toEqual(['host-session', 'endpoint-session']);
    expect(merge.stateOf('ankh-grep').records).toHaveLength(1);
  });

  it('keeps the last list and marks the endpoint stale when it does not answer', async () => {
    let fail = false;
    let clock = 0;
    const merge = createExternalSessionMerge({
      registry: registryOf([endpoint()]),
      listSessions: async () => {
        if (fail) throw new Error('connection refused');
        return [record('s1', '/root/project')];
      },
      now: () => clock,
      ttlMs: 1000,
    });
    const first = await merge.merge({ data: [] });
    expect(first.data.map((entry) => entry.id)).toEqual(['s1']);
    fail = true;
    clock = 2000;
    const second = await merge.merge({ data: [] });
    expect(second.data.map((entry) => entry.id)).toEqual(['s1']);
    expect(second.spaces[0]).toMatchObject({ id: 'ankh-grep', state: 'stale' });
  });
});

describe('#5080 health check', () => {
  it('reports healthy when server.info answers and unhealthy with the reason when it does not', async () => {
    const healthy = await checkEndpointHealth(endpoint(), {
      makeClient: () => ({ server: { info: async () => ({ ok: true }) } }),
    });
    expect(healthy).toMatchObject({ ok: true });
    const unhealthy = await checkEndpointHealth(endpoint(), {
      makeClient: () => ({
        server: {
          info: async () => {
            throw new Error('401 Unauthorized');
          },
        },
      }),
    });
    expect(unhealthy).toMatchObject({ ok: false, error: '401 Unauthorized' });
  });

  it('times out instead of hanging on a server that accepts the connection and never answers', async () => {
    const result = await checkEndpointHealth(endpoint(), {
      timeoutMs: 20,
      makeClient: () => ({ server: { info: () => new Promise(() => {}) } }),
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/no answer within 20ms/);
  });
});
