/**
 * Shared helpers for the authorization analyzers.
 *
 * Keeps the horizontal and vertical analyzers focused on their decision logic
 * by centralizing privilege inference, response conversion, resource-marker
 * extraction and provenance lookup.
 */
import type { ResponseLike } from './compare';
import type { UserInfo } from './engine';
import type {
  Evidence,
  NavigationGraph,
  ObservedRequest,
  ReplayResult,
  ResponseSnapshot,
} from '../core/types';

const PREVIEW_LEN = 600;

/** Build a compact, already-redacted response snapshot from an observed request. */
export function snapshotObserved(req: ObservedRequest): ResponseSnapshot {
  return {
    status: req.status,
    contentType: req.contentType,
    size: req.responseSize,
    bodyPreview: req.responseBody ? req.responseBody.slice(0, PREVIEW_LEN) : undefined,
  };
}

/** Build a compact, already-redacted response snapshot from a replay result. */
export function snapshotReplay(r: ReplayResult): ResponseSnapshot {
  return {
    status: r.status,
    contentType: r.contentType,
    size: r.responseSize,
    bodyPreview: r.responseBody ? r.responseBody.slice(0, PREVIEW_LEN) : undefined,
  };
}

const ROLE_PRIVILEGE: Record<string, number> = {
  anonymous: 0,
  anon: 0,
  guest: 0,
  user: 10,
  member: 10,
  customer: 10,
  editor: 30,
  manager: 50,
  staff: 50,
  moderator: 50,
  admin: 100,
  administrator: 100,
  superadmin: 120,
  root: 120,
};

const PRIVILEGED_PATH_RE = /\/(admin|administrator|manage|management|internal|staff|moderat|root|superuser|backoffice|console|debug)\b/i;

/** Infer a numeric privilege level: explicit config wins, else role heuristic. */
export function privilegeOf(info: UserInfo): number {
  if (typeof info.privilegeLevel === 'number') return info.privilegeLevel;
  const role = (info.role ?? '').toLowerCase();
  if (role in ROLE_PRIVILEGE) return ROLE_PRIVILEGE[role];
  // An unauthenticated context (no cookies) is commonly named "anon*".
  if (/anon|public|guest/.test(info.name.toLowerCase())) return 0;
  return 10;
}

/** Path segments that introduce a tenant/org scope. */
const TENANT_COLLECTIONS = new Set([
  'orgs', 'org', 'organizations', 'organisation', 'organisations',
  'tenants', 'tenant', 'accounts', 'account', 'workspaces', 'workspace',
  'companies', 'company', 'teams', 'team', 'customers', 'customer',
]);

/**
 * Whether a URL is scoped to a given tenant, i.e. its path contains a
 * tenant-collection segment immediately followed by that tenant's id
 * (e.g. tenant "1" matches /api/orgs/1/projects but NOT /api/users/1).
 * The collection prefix avoids mistaking a per-user object id for a tenant id.
 */
export function resourceTenantScoped(url: string, tenant: string): boolean {
  let segs: string[];
  try {
    segs = new URL(url).pathname.split('/').filter(Boolean);
  } catch {
    return false;
  }
  for (let i = 0; i < segs.length - 1; i++) {
    if (TENANT_COLLECTIONS.has(segs[i].toLowerCase()) && segs[i + 1] === tenant) return true;
  }
  return false;
}

export function isPrivilegedPath(pathOrUrl: string): boolean {
  let path = pathOrUrl;
  try {
    path = new URL(pathOrUrl).pathname;
  } catch {
    /* already a path */
  }
  return PRIVILEGED_PATH_RE.test(path);
}

/** Convert an observed request into a comparable response shape. */
export function sourceResponse(req: ObservedRequest): ResponseLike {
  return {
    status: req.status,
    contentType: req.contentType,
    body: req.responseBody,
    size: req.responseSize,
    headers: req.responseHeaders,
    location: headerValue(req.responseHeaders, 'location'),
  };
}

/** Convert a replay result into a comparable response shape. */
export function replayResponse(r: ReplayResult): ResponseLike {
  return {
    status: r.status,
    contentType: r.contentType,
    body: r.responseBody,
    size: r.responseSize,
    headers: r.responseHeaders,
    location: r.responseHeaders ? headerValue(r.responseHeaders, 'location') : undefined,
  };
}

function headerValue(
  headers: Array<{ name: string; value: string }> | undefined,
  name: string,
): string | undefined {
  return headers?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;
}

/**
 * Resource markers: concrete identifier values from the request that, if present
 * in a test user's response, prove they received *the same* object rather than
 * their own. Drawn from normalized path variables and the last path segment.
 */
export function resourceMarkers(req: ObservedRequest): string[] {
  const markers = new Set<string>();
  if (req.normalized) {
    for (const v of Object.values(req.normalized.variables)) {
      if (v && v.length >= 2 && !/^\d{1,2}$/.test(v)) markers.add(v); // skip 1-2 digit values (too common)
    }
  }
  try {
    const segs = new URL(req.url).pathname.split('/').filter(Boolean);
    const last = segs[segs.length - 1];
    if (last && /[0-9a-f]{3,}/i.test(last)) markers.add(decodeURIComponent(last));
  } catch {
    /* ignore */
  }
  return [...markers];
}

/** Which of the given markers appear in a response body. */
export function markersPresent(body: string | undefined, markers: string[]): string[] {
  if (!body) return [];
  return markers.filter((m) => body.includes(m));
}

/**
 * Whether a response represents a genuine data resource worth authz analysis,
 * as opposed to a static/SPA HTML shell that is served identically for every
 * route and user. A server-rendered per-object HTML page is kept only when it
 * actually embeds the resource's identifier; JSON/XHR/fetch responses are always
 * data-bearing. This is a key false-positive guard for single-page apps.
 */
export function isDataBearingResource(req: ObservedRequest, markers: string[]): boolean {
  const ct = (req.contentType ?? '').toLowerCase();
  const isHtml = req.resourceType === 'document' || ct.includes('text/html');
  if (!isHtml) return true;
  return markersPresent(req.responseBody, markers).length > 0;
}

/** Find the graph edge label that first produced a request (for provenance). */
export function provenanceOf(
  graphs: Map<string, NavigationGraph>,
  requestId: string,
): string | undefined {
  for (const graph of graphs.values()) {
    for (const edge of graph.edges) {
      if (edge.requestIds.includes(requestId)) {
        const node = graph.nodes.find((n) => n.id === edge.from);
        return `${edge.label}${node?.route ? ` @ ${node.route}` : ''}`;
      }
    }
  }
  return undefined;
}

export interface RepresentativePick {
  request: ObservedRequest;
}

/**
 * Pick a representative concrete request for a user + signature: prefer a
 * successful GET (safe to replay and establishes a real baseline).
 */
export function pickRepresentative(
  requestsById: Map<string, ObservedRequest>,
  requestIds: string[],
): ObservedRequest | undefined {
  let firstGet: ObservedRequest | undefined;
  for (const id of requestIds) {
    const req = requestsById.get(id);
    if (!req) continue;
    const method = req.method.toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') continue;
    if (!firstGet) firstGet = req;
    if (req.status !== undefined && req.status >= 200 && req.status < 300) return req;
  }
  return firstGet;
}

export function evidence(label: string, detail: string): Evidence {
  return { label, detail };
}
