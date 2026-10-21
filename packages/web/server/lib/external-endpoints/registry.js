import { promises as fs } from 'node:fs';
import { isIP } from 'node:net';
import { promises as dns } from 'node:dns';
import { z } from 'zod';

// #5080 — the server-level registry of external OpenCode servers.
//
// Deliberately NOT a space or a place: a space is a container tenant this host
// creates and contains, while an endpoint is a server an operator already runs
// and authenticates to. There is no Docker here, and nothing on this path may
// require a container runtime. The registry is the only new state; the event
// and session fan-in reuse spaces/space-events.js and spaces/space-sessions.js.

export const EXTERNAL_ENDPOINT_FILE = 'external-endpoints.json';

const BASIC_AUTH = z.object({
  type: z.literal('basic'),
  username: z.string().min(1),
  password: z.string(),
});

const endpointSchema = z.object({
  id: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, 'id must be lower-case letters, digits and inner dashes'),
  label: z.string().min(1).max(120),
  url: z.string().min(1),
  auth: BASIC_AUTH,
});

export class ExternalEndpointError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ExternalEndpointError';
    this.code = code;
  }
}

const stripBrackets = (hostname) => String(hostname).replace(/^\[|\]$/g, '');

const parseIpv4 = (address) => {
  const parts = String(address).split('.').map(Number);
  if (parts.length !== 4 || parts.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
  return parts;
};

const isPrivateIpv4 = (parts) => {
  if (!parts) return false;
  const [first, second] = parts;
  if (first === 0 || first === 10 || first === 127) return true;
  if (first === 169 && second === 254) return true;
  if (first === 172 && second >= 16 && second <= 31) return true;
  if (first === 192 && second === 168) return true;
  // Carrier-grade NAT: not public, and exactly the kind of address the old
  // aggregate used to insist was a private host.
  if (first === 100 && second >= 64 && second <= 127) return true;
  return false;
};

const isPrivateIpv6 = (address) => {
  const value = String(address).toLowerCase().split('%')[0];
  if (value === '::' || value === '::1') return true;
  if (value.startsWith('fc') || value.startsWith('fd')) return true;
  if (/^fe[89ab]/.test(value)) return true;
  if (value.startsWith('::ffff:')) return isPrivateIpv4(parseIpv4(value.slice('::ffff:'.length)));
  return false;
};

export const isPrivateAddress = (address) => {
  const family = isIP(String(address));
  if (family === 4) return isPrivateIpv4(parseIpv4(address));
  if (family === 6) return isPrivateIpv6(address);
  return false;
};

const ipv4ToInt = (parts) => (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);

const inIpv4Cidr = (address, cidr) => {
  const [base, bitsRaw] = String(cidr).split('/');
  const baseParts = parseIpv4(base);
  const addressParts = parseIpv4(address);
  const bits = Number(bitsRaw);
  if (!baseParts || !addressParts || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(baseParts) & mask) === (ipv4ToInt(addressParts) & mask);
};

const ipv6ToBigInt = (address) => {
  const value = String(address).toLowerCase().split('%')[0];
  if (isIP(value) !== 6 || value.includes('.')) return null;
  const [leftRaw, rightRaw] = value.split('::');
  const left = leftRaw ? leftRaw.split(':') : [];
  const right = rightRaw ? rightRaw.split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;
  let result = 0n;
  for (const group of groups) {
    const parsed = Number.parseInt(group, 16);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xffff) return null;
    result = (result << 16n) | BigInt(parsed);
  }
  return result;
};

const inIpv6Cidr = (address, cidr) => {
  const [base, bitsRaw] = String(cidr).split('/');
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  const baseValue = ipv6ToBigInt(base);
  const addressValue = ipv6ToBigInt(address);
  if (baseValue === null || addressValue === null) return false;
  const shift = BigInt(128 - bits);
  return baseValue >> shift === addressValue >> shift;
};

/** Whether a hostname or resolved address is named by the private-host allowlist. */
export const matchesPrivateAllowlist = (allowlist, hostname, address) => {
  const host = stripBrackets(hostname).toLowerCase();
  const candidate = String(address || '').toLowerCase();
  for (const entryRaw of allowlist || []) {
    const entry = String(entryRaw || '').trim().toLowerCase();
    if (!entry) continue;
    if (entry === host || entry === candidate) return true;
    if (entry.includes('/')) {
      if (isIP(candidate) === 4 && inIpv4Cidr(candidate, entry)) return true;
      if (isIP(candidate) === 6 && inIpv6Cidr(candidate, entry)) return true;
    }
  }
  return false;
};

const normalizeUrl = (raw) => {
  let parsed;
  try {
    parsed = new URL(String(raw));
  } catch {
    throw new ExternalEndpointError('external_endpoint_url_invalid', 'url must be an absolute http(s) URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ExternalEndpointError('external_endpoint_url_invalid', 'url must use http or https');
  }
  if (parsed.username || parsed.password) {
    throw new ExternalEndpointError('external_endpoint_url_credentials', 'url must not carry credentials; use auth');
  }
  if (parsed.search || parsed.hash) {
    throw new ExternalEndpointError('external_endpoint_url_invalid', 'url must not carry a query or fragment');
  }
  const pathname = parsed.pathname.replace(/\/+$/, '');
  return `${parsed.origin}${pathname}`;
};

/**
 * Refuse a private or loopback destination unless the private-host allowlist
 * names it. The check runs on the RESOLVED addresses, not only on the name, so
 * `localhost` and a hostname that resolves into a private range are both caught.
 * `lookup` is injectable so the registry's tests do no DNS.
 */
export async function assertExternalEndpointAllowed({ url, allowPrivateHosts = [], lookup = dns.lookup }) {
  const parsed = new URL(url);
  const hostname = stripBrackets(parsed.hostname);
  const literalFamily = isIP(hostname);
  let addresses;
  if (literalFamily) {
    addresses = [{ address: hostname, family: literalFamily }];
  } else {
    try {
      addresses = await lookup(hostname, { all: true });
    } catch {
      throw new ExternalEndpointError('external_endpoint_unresolvable', `the endpoint host ${hostname} did not resolve`);
    }
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new ExternalEndpointError('external_endpoint_unresolvable', `the endpoint host ${hostname} resolved to no address`);
  }
  for (const entry of addresses) {
    if (!isPrivateAddress(entry.address)) continue;
    if (matchesPrivateAllowlist(allowPrivateHosts, hostname, entry.address)) continue;
    throw new ExternalEndpointError(
      'external_endpoint_private_host',
      `the endpoint host ${hostname} resolves to the private address ${entry.address}; add it (or its range) to the private-host allowlist to permit it`
    );
  }
  return { hostname, addresses: addresses.map((entry) => entry.address) };
}

const slugify = (value) =>
  String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);

const publicEndpoint = (endpoint) => ({
  id: endpoint.id,
  label: endpoint.label,
  url: endpoint.url,
  auth: { type: endpoint.auth.type, username: endpoint.auth.username },
  hasPassword: endpoint.auth.password.length > 0,
});

const cloneEndpoint = (endpoint) => ({
  ...endpoint,
  auth: { ...endpoint.auth },
});

/**
 * The registry file is the only new state this feature adds. It is written with
 * mode 0600 because `auth.password` is carried for the endpoint's Basic auth;
 * `listPublic()` is what the HTTP surface returns and never includes it.
 */
export function createExternalEndpointRegistry({
  filePath,
  allowPrivateHosts = [],
  lookup = dns.lookup,
  readFile = fs.readFile,
  writeFile = fs.writeFile,
  rename = fs.rename,
  logger = console,
} = {}) {
  if (!filePath) throw new Error('filePath is required');
  let endpoints = [];
  let loaded = false;

  const persist = async () => {
    const temporary = `${filePath}.tmp`;
    const body = `${JSON.stringify({ endpoints }, null, 2)}\n`;
    await writeFile(temporary, body, { mode: 0o600 });
    try {
      await rename(temporary, filePath);
    } catch (error) {
      await fs.rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  };

  const load = async () => {
    if (loaded) return endpoints;
    loaded = true;
    let raw;
    try {
      raw = await readFile(filePath, 'utf8');
    } catch (error) {
      if (error?.code === 'ENOENT') return (endpoints = []);
      throw error;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      logger.warn?.(`[external-endpoints] ${filePath} is not valid JSON; starting with no endpoints`);
      return (endpoints = []);
    }
    const candidates = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.endpoints) ? parsed.endpoints : [];
    const valid = [];
    for (const candidate of candidates) {
      const result = endpointSchema.safeParse(candidate);
      if (!result.success) {
        logger.warn?.(`[external-endpoints] dropped a malformed registry entry: ${result.error.issues[0]?.message ?? 'invalid'}`);
        continue;
      }
      try {
        valid.push({ ...result.data, url: normalizeUrl(result.data.url) });
      } catch (error) {
        logger.warn?.(`[external-endpoints] dropped ${result.data.id}: ${error.message}`);
      }
    }
    endpoints = valid;
    return endpoints;
  };

  const add = async (input) => {
    await load();
    const label = typeof input?.label === 'string' ? input.label.trim() : '';
    const requestedId = typeof input?.id === 'string' && input.id.trim() ? input.id.trim() : slugify(label);
    const candidate = endpointSchema.safeParse({
      id: requestedId,
      label,
      url: input?.url,
      auth: input?.auth,
    });
    if (!candidate.success) {
      throw new ExternalEndpointError('external_endpoint_invalid', candidate.error.issues[0]?.message ?? 'invalid endpoint');
    }
    const url = normalizeUrl(candidate.data.url);
    if (endpoints.some((endpoint) => endpoint.id === candidate.data.id)) {
      throw new ExternalEndpointError('external_endpoint_id_taken', `an endpoint with the id ${candidate.data.id} is already registered`);
    }
    if (endpoints.some((endpoint) => endpoint.url === url)) {
      throw new ExternalEndpointError('external_endpoint_url_taken', `${url} is already registered`);
    }
    await assertExternalEndpointAllowed({ url, allowPrivateHosts, lookup });
    const endpoint = { ...candidate.data, url };
    endpoints = [...endpoints, endpoint];
    await persist();
    return cloneEndpoint(endpoint);
  };

  const remove = async (id) => {
    await load();
    const before = endpoints.length;
    endpoints = endpoints.filter((endpoint) => endpoint.id !== id);
    if (endpoints.length === before) return false;
    await persist();
    return true;
  };

  const get = async (id) => {
    await load();
    const endpoint = endpoints.find((entry) => entry.id === id);
    return endpoint ? cloneEndpoint(endpoint) : null;
  };

  return {
    filePath,
    load,
    list: async () => {
      await load();
      return endpoints.map(cloneEndpoint);
    },
    listPublic: async () => {
      await load();
      return endpoints.map(publicEndpoint);
    },
    get,
    add,
    remove,
  };
}

export { publicEndpoint, normalizeUrl };
