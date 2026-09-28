/**
 * Core domain types shared across the auditor.
 *
 * These types are intentionally framework-agnostic so that engines (browser,
 * network, analysis, reporting) depend on data shapes rather than on each
 * other. New detection engines can be added by consuming {@link EndpointObservation}
 * and {@link NavigationGraph} and emitting {@link Finding} objects.
 */

/** Severity of a finding. Ordered from least to most serious. */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** Confidence that a finding is real (and not a false positive). */
export type Confidence = 'info' | 'low' | 'medium' | 'high';

/** How safe it is to trigger an interaction or replay a request. */
export type SafetyClass = 'safe' | 'confirm' | 'destructive';

/** HTTP method, upper-cased. */
export type HttpMethod = string;

/**
 * A single HTTP header, already passed through redaction. Sensitive header
 * values (cookies, authorization, tokens) are replaced with a stable
 * placeholder before this object is ever persisted or logged.
 */
export interface HeaderPair {
  name: string;
  /** Redacted value; never the raw secret for sensitive headers. */
  value: string;
  /** True when the original value was redacted. */
  redacted?: boolean;
}

/** A query or body parameter, with sensitive values redacted. */
export interface ParamPair {
  name: string;
  value: string;
  redacted?: boolean;
  location: 'query' | 'body' | 'path';
}

/** Timing information for a request, in milliseconds relative to request start. */
export interface RequestTiming {
  startedAt: number; // epoch ms
  durationMs?: number;
}

/** Where a request originated from, as reported by CDP when available. */
export interface RequestInitiator {
  type?: string; // 'parser' | 'script' | 'preload' | 'other' | ...
  url?: string;
  lineNumber?: number;
}

/**
 * A normalized representation of a request URL where volatile path/query
 * segments are replaced by typed placeholders (e.g. /api/users/{id}). This is
 * the key used to decide that two concrete requests target "the same" endpoint.
 */
export interface NormalizedRequest {
  /** e.g. "GET /api/users/{id}" */
  signature: string;
  method: HttpMethod;
  /** host without volatile parts; kept for scope/grouping. */
  host: string;
  /** templated path, e.g. /api/users/{id} */
  pathTemplate: string;
  /** query keys sorted, values templated where volatile. */
  queryTemplate: string;
  /** concrete placeholder values captured during templating, keyed by placeholder. */
  variables: Record<string, string>;
}

/**
 * A fully observed network request/response pair captured from the browser.
 * Secrets are redacted before this object is created.
 */
export interface ObservedRequest {
  id: string;
  /** logical user context that produced this request (config user name). */
  user: string;
  method: HttpMethod;
  url: string;
  origin?: string;
  /** target host. */
  host: string;
  resourceType?: string; // document, xhr, fetch, websocket, script, image...
  requestHeaders: HeaderPair[];
  params: ParamPair[];
  /** Redacted request body preview (may be truncated). */
  requestBody?: string;
  status?: number;
  statusText?: string;
  responseHeaders: HeaderPair[];
  /** Response body size in bytes when known. */
  responseSize?: number;
  /** Redacted, size-limited response body snapshot for analysis. */
  responseBody?: string;
  /** MIME/content-type of the response, when known. */
  contentType?: string;
  redirectedFrom?: string;
  redirectedTo?: string;
  timing: RequestTiming;
  initiator?: RequestInitiator;
  /** page/route URL that was active when the request fired. */
  sourceRoute?: string;
  /** discovery-graph node id that owns this request, when known. */
  nodeId?: string;
  /** normalized signature, filled by the normalizer. */
  normalized?: NormalizedRequest;
  /** true when the request left the configured scope and was flagged. */
  outOfScope?: boolean;
}

/** A node in the navigation/discovery graph: a distinct observed browser state. */
export interface GraphNode {
  id: string;
  user: string;
  url: string;
  /** normalized route for grouping, e.g. /dashboard or /orders/{id}. */
  route?: string;
  title?: string;
  timestamp: number;
  /** short description of browser state (e.g. modal open, tab index). */
  state?: string;
  /** ids of interactions/actions that led to this node. */
  incomingEdges: string[];
  outgoingEdges: string[];
}

/** How a resource/state was discovered. */
export type DiscoverySource =
  | 'seed'
  | 'anchor'
  | 'dom-url'
  | 'history-pushstate'
  | 'history-replacestate'
  | 'fetch'
  | 'xhr'
  | 'websocket'
  | 'eventsource'
  | 'network-resource'
  | 'interaction'
  | 'dom-mutation'
  | 'new-window'
  | 'script-url'
  | 'redirect';

/** An edge in the navigation graph: the action/event that changed state. */
export interface GraphEdge {
  id: string;
  from: string; // node id
  to?: string; // node id (may be undefined for background requests)
  source: DiscoverySource;
  /** human-readable description, e.g. 'click button[data-test=save]'. */
  label: string;
  safety: SafetyClass;
  timestamp: number;
  /** request ids emitted as a result of this edge. */
  requestIds: string[];
}

/** The full navigation graph for one user. */
export interface NavigationGraph {
  user: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * An endpoint as seen from a single user context: a normalized signature plus
 * the concrete observations that produced it.
 */
export interface EndpointObservation {
  signature: string;
  method: HttpMethod;
  pathTemplate: string;
  host: string;
  /** all concrete requests that mapped to this signature. */
  requestIds: string[];
  /** representative observed request id (first success, else first). */
  representativeId: string;
  /** discovery sources that surfaced this endpoint. */
  sources: DiscoverySource[];
  firstSeen: number;
}

/** Per-user inventory of endpoints. */
export interface UserInventory {
  user: string;
  role?: string;
  privilegeLevel?: number;
  endpoints: Map<string, EndpointObservation>;
}

/** A structured, serializable difference between two responses. */
export interface ResponseDiff {
  statusChanged: boolean;
  sourceStatus?: number;
  testStatus?: number;
  sizeDeltaBytes?: number;
  /** high-level classification of the comparison. */
  verdict:
    | 'identical'
    | 'similar'
    | 'different'
    | 'access-granted'
    | 'access-denied'
    | 'inconclusive';
  /** structural JSON differences (added/removed/changed keys), if applicable. */
  jsonKeyDiffs?: string[];
  /** short human-readable notes explaining the verdict. */
  notes: string[];
  /** similarity score 0..1 after ignoring dynamic fields. */
  similarity: number;
}

/** A single piece of evidence supporting a finding. */
export interface Evidence {
  label: string;
  detail: string;
}

/** A compact, redacted snapshot of a response, embedded in findings/reports. */
export interface ResponseSnapshot {
  status?: number;
  contentType?: string;
  size?: number;
  /** redacted, truncated body preview. */
  bodyPreview?: string;
}

/** A detection produced by an analyzer. */
export interface Finding {
  id: string;
  type: string; // e.g. AUTHZ-HORIZONTAL, AUTHZ-VERTICAL
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** user whose context originally discovered the resource. */
  sourceUser?: string;
  /** user context used to test access. */
  testUser?: string;
  method?: HttpMethod;
  url?: string;
  normalizedRoute?: string;
  /** action/edge that triggered the original observation. */
  triggeringAction?: string;
  observedRequestId?: string;
  comparisonRequestId?: string;
  /** redacted snapshot of the source (authorized) response. */
  observedResponse?: ResponseSnapshot;
  /** redacted snapshot of the test/replay response being compared. */
  comparisonResponse?: ResponseSnapshot;
  diff?: ResponseDiff;
  evidence: Evidence[];
  timestamp: number;
}

/** A replay attempt of one request under a different user context. */
export interface ReplayResult {
  originalRequestId: string;
  originalUser: string;
  replayUser: string;
  method: HttpMethod;
  url: string;
  requested: boolean; // false if skipped by policy
  skippedReason?: string;
  status?: number;
  responseSize?: number;
  responseBody?: string;
  contentType?: string;
  responseHeaders?: HeaderPair[];
  timestamp: number;
}

/** Aggregate result of a scan, ready for reporting. */
export interface ScanResult {
  target: string;
  startedAt: number;
  finishedAt: number;
  users: string[];
  stats: {
    nodes: number;
    edges: number;
    requests: number;
    endpoints: number;
    replays: number;
    outOfScopeBlocked: number;
  };
  findings: Finding[];
  /** per-user endpoint counts for the report summary. */
  inventorySummary: Array<{ user: string; role?: string; endpoints: number }>;
}
