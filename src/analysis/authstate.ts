/**
 * Authentication-state analyzer.
 *
 * Detects endpoints reachable with NO authentication that were observed in
 * authenticated contexts — i.e. a missing authentication check, as opposed to a
 * privilege/role gap (which is the vertical analyzer's job). It replays each
 * authenticated endpoint under an unauthenticated identity (a configured user
 * with no cookies/headers/login) and reports when the response is served rather
 * than denied.
 *
 * To avoid flagging genuinely public endpoints, a served-unauthenticated
 * response is only reported when the endpoint is sensitive (a privileged path or
 * an object reference) OR it was never part of the unauthenticated crawl surface
 * (the public UI never called it, yet the server serves it without a session).
 */
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext, UserInfo } from './engine';
import type { Confidence, Evidence, Finding, Severity } from '../core/types';
import { detectDenial } from './compare';
import {
  evidence,
  isDataBearingResource,
  isPrivilegedPath,
  pickRepresentative,
  provenanceOf,
  replayResponse,
  resourceMarkers,
  snapshotObserved,
  snapshotReplay,
} from './authz-common';

const OBJECT_REF_RE = /\{(id|uuid|objectid|hex|token|slug|seg)\d*\}/;

export class AuthStateAnalyzer implements Analyzer {
  readonly id = 'AUTHN-NO-AUTH';
  readonly title = 'Authentication state (endpoints reachable without a session)';

  async analyze(ctx: AnalysisContext): Promise<Finding[]> {
    const unauth = ctx.users.filter((u) => u.authenticated === false);
    const authed = ctx.users.filter((u) => u.authenticated);
    if (unauth.length === 0 || authed.length === 0) {
      if (unauth.length === 0) {
        ctx.logger.info(
          {},
          'auth-state analyzer skipped: configure an unauthenticated user (no cookies/headers) to test the authentication boundary',
        );
      }
      return [];
    }

    const findings: Finding[] = [];
    const processed = new Set<string>();

    for (const inv of ctx.inventory.allUsers()) {
      if (!authed.some((u) => u.name === inv.user)) continue; // authenticated observers only
      for (const [signature, obs] of inv.endpoints) {
        if (processed.has(signature)) continue;
        const base = pickRepresentative(ctx.requestsById, obs.requestIds);
        if (!base || base.status === undefined || base.status < 200 || base.status >= 300) continue;
        if (ctx.scope.isExcludedFromAnalysis(base.url)) continue;
        if (!isDataBearingResource(base, resourceMarkers(base))) continue;
        processed.add(signature);

        const unauthUser = unauth[0];
        const replay = await ctx.replayer.replay(base, unauthUser.name);
        if (!replay.requested) continue;
        const resp = replayResponse(replay);
        const reachable =
          replay.status !== undefined && replay.status >= 200 && replay.status < 300 && !detectDenial(resp);
        if (!reachable) continue;

        const sensitive = isPrivilegedPath(base.url) || OBJECT_REF_RE.test(signature);
        const unauthObserved = !!ctx.inventory.getUser(unauthUser.name)?.endpoints.has(signature);
        if (!sensitive && unauthObserved) continue; // genuinely public surface

        const { severity, confidence } = this.grade(base.url, signature);
        const ev: Evidence[] = [
          evidence('observed authenticated as', `${inv.user} reached ${base.method} ${pathOf(base.url)}`),
          evidence('unauthenticated request', `served to ${unauthUser.name} (no session): HTTP ${replay.status}, ${replay.responseSize ?? '?'} bytes`),
          evidence('sensitive endpoint', sensitive ? 'yes (privileged path or object reference)' : 'no'),
          evidence('in public UI surface', unauthObserved ? 'yes' : 'no (never requested by the unauthenticated crawl)'),
          evidence('interpretation', 'the endpoint returns data without requiring authentication'),
        ];
        const prov = provenanceOf(ctx.graphs, base.id);
        if (prov) ev.push(evidence('discovery action', prov));

        findings.push({
          id: `${this.id}-${randomUUID().slice(0, 8)}`,
          type: this.id,
          title: `Endpoint reachable without authentication: ${pathOf(base.url)}`,
          severity,
          confidence,
          sourceUser: inv.user,
          testUser: unauthUser.name,
          method: base.method,
          url: base.url,
          normalizedRoute: signature,
          triggeringAction: prov,
          observedRequestId: base.id,
          comparisonRequestId: replay.originalRequestId,
          observedResponse: snapshotObserved(base),
          comparisonResponse: snapshotReplay(replay),
          evidence: ev,
          tags: ['no-auth'],
          timestamp: Date.now(),
        });
      }
    }
    return findings;
  }

  private grade(url: string, signature: string): { severity: Severity; confidence: Confidence } {
    if (isPrivilegedPath(url)) return { severity: 'high', confidence: 'high' };
    if (OBJECT_REF_RE.test(signature)) return { severity: 'high', confidence: 'medium' };
    return { severity: 'medium', confidence: 'medium' };
  }
}

/** Names of the unauthenticated identities among the configured users. */
export function unauthenticatedUsers(users: UserInfo[]): string[] {
  return users.filter((u) => u.authenticated === false).map((u) => u.name);
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
