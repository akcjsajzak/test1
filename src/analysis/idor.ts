/**
 * Active object-id enumeration analyzer (IDOR sweep).
 *
 * Distinct from the horizontal analyzer (which replays *observed* requests
 * across users), this analyzer *constructs* new requests by probing sequential
 * numeric ids around an id a user legitimately reached, issued under that same
 * user's context. If the user is served records they were never linked to, the
 * endpoint lacks per-object authorization and its objects are enumerable.
 *
 * It is opt-in (`idor.enabled`) because it generates new traffic, and it is
 * bounded (per-endpoint and global probe caps) and safe (GET only, via the same
 * scope/budget/rate-limited replay path). Only numeric ids are enumerated; UUID
 * and slug ids are not feasibly guessable and are skipped.
 */
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext } from './engine';
import type { Confidence, Evidence, Finding, ObservedRequest, Severity } from '../core/types';
import { detectDenial, textSimilarity } from './compare';
import {
  evidence,
  isDataBearingResource,
  pickRepresentative,
  provenanceOf,
  resourceMarkers,
  snapshotObserved,
} from './authz-common';

interface AccessedId {
  id: number;
  status: number;
  size?: number;
}

export class IdorEnumerationAnalyzer implements Analyzer {
  readonly id = 'AUTHZ-IDOR-ENUM';
  readonly title = 'Active object-id enumeration (IDOR sweep)';

  async analyze(ctx: AnalysisContext): Promise<Finding[]> {
    const cfg = ctx.config.idor;
    if (!cfg.enabled) return [];
    const state = { totalProbes: 0 };

    // Pass 1: probe every (user, numeric-id endpoint) and collect outcomes.
    const candidates: Candidate[] = [];
    // Signatures where ANY user's probe was denied enforce object-level authz;
    // enumeration by an authorized (e.g. admin) user there is not a blanket IDOR.
    const enforcingSignatures = new Set<string>();

    for (const inv of ctx.inventory.allUsers()) {
      for (const [signature, obs] of inv.endpoints) {
        if (state.totalProbes >= cfg.maxTotalProbes) break;
        if (!/\{id\}/.test(signature)) continue; // numeric-id endpoints only
        const base = pickRepresentative(ctx.requestsById, obs.requestIds);
        if (!base || base.method.toUpperCase() !== 'GET') continue;
        if (base.status === undefined || base.status < 200 || base.status >= 300) continue;
        if (ctx.scope.isExcludedFromAnalysis(base.url)) continue;
        if (!isDataBearingResource(base, resourceMarkers(base))) continue;
        const target = enumerationTarget(base);
        if (!target) continue;

        const probed = await this.probeEndpoint(ctx, cfg, inv.user, base, target, state);
        if (probed.sawDenial) enforcingSignatures.add(signature);
        if (probed.accessed.length > 0) {
          candidates.push({ user: inv.user, signature, base, target, ...probed });
        }
      }
    }

    // Pass 2: emit findings only for endpoints that never denied any user
    // (i.e. perform no object-level authorization at all).
    const findings: Finding[] = [];
    for (const c of candidates) {
      if (enforcingSignatures.has(c.signature)) continue;
      findings.push(this.buildFinding(ctx, c));
    }
    return findings;
  }

  /** Probe the neighbors of one endpoint under one user; returns accessed ids. */
  private async probeEndpoint(
    ctx: AnalysisContext,
    cfg: AnalysisContext['config']['idor'],
    user: string,
    base: ObservedRequest,
    target: { segIndex: number; value: number },
    state: { totalProbes: number },
  ): Promise<{ accessed: AccessedId[]; sawDenial: boolean; neighbors: number[] }> {
    // Establish the "absent" response (empty/not-found) to filter empty
    // collections and id-agnostic responses.
    let sentinel: AbsentResponse | undefined;
    const sentinelUrl = buildProbeUrl(base.url, target.segIndex, SENTINEL_ID);
    if (sentinelUrl && state.totalProbes < cfg.maxTotalProbes) {
      const sres = await ctx.replayer.replay(syntheticRequest(base, sentinelUrl, user), user);
      if (sres.requested) {
        state.totalProbes += 1;
        sentinel = { status: sres.status, body: sres.responseBody, contentType: sres.contentType };
      }
    }

    const neighbors = neighborIds(target.value, cfg.numericNeighbors, cfg.maxProbesPerEndpoint);
    const accessed: AccessedId[] = [];
    let sawDenial = false;
    for (const v of neighbors) {
      if (state.totalProbes >= cfg.maxTotalProbes) break;
      const probeUrl = buildProbeUrl(base.url, target.segIndex, v);
      if (!probeUrl) continue;
      const res = await ctx.replayer.replay(syntheticRequest(base, probeUrl, user), user);
      if (!res.requested) continue;
      state.totalProbes += 1;
      if (detectDenial({ status: res.status, body: res.responseBody, contentType: res.contentType })) {
        sawDenial = true;
      } else if (isRealLeak(base, sentinel, res.status, res.responseBody, res.contentType)) {
        accessed.push({ id: v, status: res.status!, size: res.responseSize });
      }
    }
    return { accessed, sawDenial, neighbors };
  }

  private buildFinding(ctx: AnalysisContext, c: Candidate): Finding {
    const confidence: Confidence = c.accessed.length >= 2 ? 'high' : 'medium';
    const severity: Severity = c.accessed.length >= 2 ? 'high' : 'medium';
    const idList = c.accessed.map((a) => a.id).slice(0, 12).join(', ');
    const ev: Evidence[] = [
      evidence('baseline', `${c.user} legitimately reached ${c.base.method} ${pathOf(c.base.url)}`),
      evidence('probed', `${c.neighbors.length} neighboring id(s) around ${c.target.value} under ${c.user}'s own session`),
      evidence('accessed', `${c.accessed.length} record(s) never linked to ${c.user}: id(s) ${idList}`),
      evidence('interpretation', 'objects are retrievable by guessing sequential ids — the endpoint performs no per-object authorization'),
    ];
    const prov = provenanceOf(ctx.graphs, c.base.id);
    if (prov) ev.push(evidence('discovery action', prov));
    return {
      id: `${this.id}-${randomUUID().slice(0, 8)}`,
      type: this.id,
      title: `${c.user} can enumerate objects at ${templatePath(c.signature)} by guessing ids`,
      severity,
      confidence,
      sourceUser: c.user,
      testUser: c.user,
      method: c.base.method,
      url: c.base.url,
      normalizedRoute: c.signature,
      triggeringAction: prov,
      observedRequestId: c.base.id,
      observedResponse: snapshotObserved(c.base),
      evidence: ev,
      tags: ['enumeration'],
      timestamp: Date.now(),
    };
  }
}

interface Candidate {
  user: string;
  signature: string;
  base: ObservedRequest;
  target: { segIndex: number; value: number };
  accessed: AccessedId[];
  sawDenial: boolean;
  neighbors: number[];
}

/** The last numeric {id} position in the request, with its concrete value. */
function enumerationTarget(base: ObservedRequest): { segIndex: number; value: number } | null {
  if (!base.normalized) return null;
  let segs: string[];
  try {
    segs = new URL(base.url).pathname.split('/');
  } catch {
    return null;
  }
  const tsegs = base.normalized.pathTemplate.split('/');
  let target: { segIndex: number; value: number } | null = null;
  for (let i = 0; i < segs.length; i++) {
    if (tsegs[i] === '{id}' && /^\d+$/.test(segs[i])) {
      target = { segIndex: i, value: Number(segs[i]) };
    }
  }
  return target;
}

/** Sequential neighbors around a value (positive ids only), bounded. */
function neighborIds(value: number, radius: number, cap: number): number[] {
  const out: number[] = [];
  for (let k = 1; k <= radius; k++) {
    if (value - k >= 1) out.push(value - k);
    out.push(value + k);
  }
  return out.slice(0, cap);
}

function buildProbeUrl(baseUrl: string, segIndex: number, value: number): string | null {
  try {
    const u = new URL(baseUrl);
    const segs = u.pathname.split('/');
    segs[segIndex] = String(value);
    u.pathname = segs.join('/');
    return u.toString();
  } catch {
    return null;
  }
}

function syntheticRequest(base: ObservedRequest, url: string, user: string): ObservedRequest {
  return {
    id: `${user}:idor:${randomUUID().slice(0, 8)}`,
    user,
    method: 'GET',
    url,
    host: base.host,
    resourceType: base.resourceType,
    requestHeaders: base.requestHeaders,
    params: [],
    responseHeaders: [],
    timing: { startedAt: Date.now() },
  };
}

const SENTINEL_ID = 987654321;

interface AbsentResponse {
  status?: number;
  body?: string;
  contentType?: string;
}

/**
 * Whether a probe returned a genuine record that leaks data — i.e. a 2xx,
 * non-denial response that shares the baseline's resource shape AND differs
 * from the "absent" sentinel response (filtering empty collections and
 * responses that ignore the id entirely).
 */
function isRealLeak(
  base: ObservedRequest,
  sentinel: AbsentResponse | undefined,
  status: number | undefined,
  body: string | undefined,
  contentType: string | undefined,
): boolean {
  if (status === undefined || status < 200 || status >= 300) return false;
  if (!body) return false;
  if (detectDenial({ status, body, contentType })) return false;

  const bj = tryParse(base.responseBody);
  const pj = tryParse(body);
  if (bj && pj) {
    const pKeys = topKeys(pj).filter((k) => k !== 'error' && k !== '_meta');
    if (pKeys.length === 0) return false; // error-only object
    const bKeys = new Set(topKeys(bj));
    if (!pKeys.some((k) => bKeys.has(k))) return false; // must share the baseline shape
  } else if (body.length === 0) {
    return false;
  }

  // Reject responses indistinguishable from the "absent" sentinel (empty list,
  // or content returned regardless of the id).
  if (sentinel && sentinel.status !== undefined && sentinel.status >= 200 && sentinel.status < 300) {
    if (textSimilarity(sentinel.body ?? '', body) >= 0.9) return false;
  }
  return true;
}

function tryParse(s: string | undefined): unknown | undefined {
  if (!s) return undefined;
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

function topKeys(v: unknown): string[] {
  if (v && typeof v === 'object' && !Array.isArray(v)) return Object.keys(v as Record<string, unknown>);
  return [];
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function templatePath(signature: string): string {
  const sp = signature.split(' ');
  const hostPath = sp[sp.length - 1];
  const idx = hostPath.indexOf('/');
  return idx >= 0 ? hostPath.slice(idx) : hostPath;
}
