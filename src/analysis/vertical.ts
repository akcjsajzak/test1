/**
 * Vertical authorization analyzer (privilege escalation).
 *
 * Strategy: for each endpoint a *higher-privilege* user reached with a
 * successful GET — especially capabilities the lower-privilege user's own UI
 * never surfaced — replay it under each *lower-privilege* user (including an
 * anonymous context, if configured) and compare. If the lower-privilege user
 * is served the privileged response instead of being denied, that indicates a
 * missing role/authorization check.
 *
 * The result is stated factually: a served response plus the absence of any
 * denial signal is reported as an authorization inconsistency with graded
 * confidence, not asserted as an exploit without evidence.
 */
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext } from './engine';
import type { Confidence, Evidence, Finding, ObservedRequest } from '../core/types';
import { compareResponses } from './compare';
import {
  evidence,
  isDataBearingResource,
  isPrivilegedPath,
  pickRepresentative,
  privilegeOf,
  provenanceOf,
  replayResponse,
  resourceMarkers,
  snapshotObserved,
  snapshotReplay,
  sourceResponse,
} from './authz-common';

export class VerticalAnalyzer implements Analyzer {
  readonly id = 'AUTHZ-VERTICAL';
  readonly title = 'Vertical authorization (privilege escalation)';

  async analyze(ctx: AnalysisContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const privileges = new Map(ctx.users.map((u) => [u.name, privilegeOf(u)]));
    const inventory = ctx.inventory;

    // Iterate once per distinct endpoint signature. The canonical "source" is the
    // highest-privilege user that reached it, so each lower user is tested once
    // per endpoint (no duplicate findings for endpoints seen in many contexts).
    for (const [signature, observers] of inventory.signatureIndex()) {
      const canonical = this.canonicalSource(ctx, inventory, privileges, signature, observers);
      if (!canonical) continue;
      const { sourceReq, highPriv, sourceUser } = canonical;

      if (ctx.scope.isExcludedFromAnalysis(sourceReq.url)) continue;
      if (!isDataBearingResource(sourceReq, resourceMarkers(sourceReq))) continue;

      const privilegedLooking = isPrivilegedPath(sourceReq.url);

      {
        for (const testUser of ctx.users) {
          // Unauthenticated access is the auth-state analyzer's domain.
          if (testUser.authenticated === false) continue;
          const testPriv = privileges.get(testUser.name) ?? 10;
          if (testPriv >= highPriv) continue; // only test strictly lower privilege

          // Candidate if the endpoint looks privileged OR the lower user's own
          // crawl never surfaced it (a capability their UI does not expose).
          const testInv = inventory.getUser(testUser.name);
          const testHasItNaturally = !!testInv?.endpoints.has(signature);
          if (!privilegedLooking && testHasItNaturally) continue;

          const replay = await ctx.replayer.replay(sourceReq, testUser.name);
          if (!replay.requested) continue;

          const diff = compareResponses(sourceResponse(sourceReq), replayResponse(replay), {
            ignoreFields: ctx.compareOptions.ignoreFields,
            ignoreHeaders: ctx.compareOptions.ignoreHeaders,
          });

          // A denial is the expected, secure outcome — no finding.
          if (diff.verdict === 'access-denied') continue;
          if (diff.verdict !== 'access-granted' && diff.verdict !== 'identical' && diff.verdict !== 'similar') {
            continue;
          }
          // "similar" only counts when the path is privileged (reduces noise).
          if (diff.verdict === 'similar' && !privilegedLooking) continue;

          const confidence = this.scoreConfidence(diff.verdict, privilegedLooking, testPriv);
          const severity = privilegedLooking ? 'high' : 'medium';

          const ev: Evidence[] = [
            evidence('capability observed as', `${sourceUser} (privilege ${highPriv}) reached ${sourceReq.method} ${pathOf(sourceReq.url)}`),
            evidence('tested as', `${testUser.name} (privilege ${testPriv})`),
            evidence('source response', `HTTP ${sourceReq.status}, ${sourceReq.responseSize ?? '?'} bytes`),
            evidence('test response', `HTTP ${replay.status}, ${replay.responseSize ?? '?'} bytes`),
            evidence('comparison', `${diff.verdict}, similarity ${(diff.similarity * 100).toFixed(0)}%`),
            evidence('privileged path', privilegedLooking ? 'yes (path matches admin/internal pattern)' : 'no'),
            evidence('exposed in tested user UI', testHasItNaturally ? 'yes' : 'no (capability not surfaced to this user)'),
          ];
          for (const note of diff.notes) ev.push(evidence('note', note));
          const prov = provenanceOf(ctx.graphs, sourceReq.id);
          if (prov) ev.push(evidence('discovery action', prov));

          findings.push({
            id: `${this.id}-${randomUUID().slice(0, 8)}`,
            type: this.id,
            title: `${testUser.name} can invoke higher-privilege capability ${pathOf(sourceReq.url)}`,
            severity,
            confidence,
            sourceUser: sourceUser,
            testUser: testUser.name,
            method: sourceReq.method,
            url: sourceReq.url,
            normalizedRoute: signature,
            triggeringAction: prov,
            observedRequestId: sourceReq.id,
            comparisonRequestId: replay.originalRequestId,
            observedResponse: snapshotObserved(sourceReq),
            comparisonResponse: snapshotReplay(replay),
            diff,
            evidence: ev,
            timestamp: Date.now(),
          });
        }
      }
    }
    return findings;
  }

  /**
   * Pick the highest-privilege observer of a signature that has a usable (2xx
   * GET) representative request — the canonical "this capability belongs to"
   * source for the endpoint.
   */
  private canonicalSource(
    ctx: AnalysisContext,
    inventory: AnalysisContext['inventory'],
    privileges: Map<string, number>,
    signature: string,
    observers: Set<string>,
  ): { sourceReq: ObservedRequest; highPriv: number; sourceUser: string } | undefined {
    let best: { sourceReq: ObservedRequest; highPriv: number; sourceUser: string } | undefined;
    for (const user of observers) {
      const obs = inventory.lookup(user, signature);
      if (!obs) continue;
      const rep = pickRepresentative(ctx.requestsById, obs.requestIds);
      if (!rep || rep.status === undefined || rep.status < 200 || rep.status >= 300) continue;
      const priv = privileges.get(user) ?? 10;
      if (!best || priv > best.highPriv) best = { sourceReq: rep, highPriv: priv, sourceUser: user };
    }
    return best;
  }

  private scoreConfidence(verdict: string, privilegedLooking: boolean, testPriv: number): Confidence {
    if ((verdict === 'identical' || verdict === 'access-granted') && privilegedLooking) return 'high';
    if (verdict === 'identical' || verdict === 'access-granted') return testPriv === 0 ? 'high' : 'medium';
    return privilegedLooking ? 'medium' : 'low';
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
