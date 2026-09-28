/**
 * Horizontal authorization analyzer (broken object-level authorization / IDOR).
 *
 * Strategy: for each object-referencing endpoint a *source* user reached with a
 * successful GET, replay that exact request (same concrete resource id) under
 * every *peer* user (same privilege tier) and compare. If a peer receives
 * substantially the same protected object — and the object's identifier appears
 * in their response — that is evidence of a horizontal access-control gap.
 *
 * The analysis is conservative to avoid false positives: an explicit denial, a
 * login redirect, or materially different content (the peer seeing their own
 * data) all yield no finding.
 */
import { randomUUID } from 'node:crypto';
import type { Analyzer, AnalysisContext } from './engine';
import type { Confidence, Evidence, Finding } from '../core/types';
import { compareResponses } from './compare';
import {
  evidence,
  isDataBearingResource,
  markersPresent,
  pickRepresentative,
  privilegeOf,
  provenanceOf,
  replayResponse,
  resourceMarkers,
  snapshotObserved,
  snapshotReplay,
  sourceResponse,
} from './authz-common';

/** Placeholders that indicate an object-referencing (per-resource) endpoint. */
const OBJECT_REF_RE = /\{(id|uuid|objectid|hex|token|seg)\d*\}/;

export class HorizontalAnalyzer implements Analyzer {
  readonly id = 'AUTHZ-HORIZONTAL';
  readonly title = 'Horizontal authorization (object-level / IDOR)';

  async analyze(ctx: AnalysisContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const privileges = new Map(ctx.users.map((u) => [u.name, privilegeOf(u)]));

    for (const sourceInv of ctx.inventory.allUsers()) {
      const sourcePriv = privileges.get(sourceInv.user) ?? 10;
      for (const [signature, obs] of sourceInv.endpoints) {
        if (!OBJECT_REF_RE.test(signature)) continue; // only object-referencing endpoints
        const sourceReq = pickRepresentative(ctx.requestsById, obs.requestIds);
        if (!sourceReq || sourceReq.status === undefined || sourceReq.status < 200 || sourceReq.status >= 300) {
          continue; // need a successful baseline
        }
        if (ctx.scope.isExcludedFromAnalysis(sourceReq.url)) continue;

        const markers = resourceMarkers(sourceReq);
        // Skip SPA/static HTML shells: identical markup served for every route is
        // not a protected object. Server-rendered object pages embed their id.
        if (!isDataBearingResource(sourceReq, markers)) continue;

        for (const testUser of ctx.users) {
          if (testUser.name === sourceInv.user) continue;
          // Horizontal = same tier. Cross-tier escalation is the vertical analyzer's job.
          const testPriv = privileges.get(testUser.name) ?? 10;
          if (testPriv !== sourcePriv) continue;

          const replay = await ctx.replayer.replay(sourceReq, testUser.name);
          if (!replay.requested) continue;

          const diff = compareResponses(sourceResponse(sourceReq), replayResponse(replay), {
            ignoreFields: ctx.compareOptions.ignoreFields,
            ignoreHeaders: ctx.compareOptions.ignoreHeaders,
          });

          if (diff.verdict !== 'access-granted' && diff.verdict !== 'identical') continue;

          const present = markersPresent(replay.responseBody, markers);
          const confidence = this.scoreConfidence(diff.verdict, markers.length, present.length);
          if (confidence === undefined) continue;

          const ev: Evidence[] = [
            evidence('resource discovered as', `${sourceInv.user} reached ${sourceReq.method} ${pathOf(sourceReq.url)}`),
            evidence('source response', `HTTP ${sourceReq.status}, ${sourceReq.responseSize ?? '?'} bytes`),
            evidence('test response', `HTTP ${replay.status}, ${replay.responseSize ?? '?'} bytes`),
            evidence('comparison', `${diff.verdict}, similarity ${(diff.similarity * 100).toFixed(0)}%`),
          ];
          if (present.length > 0) {
            ev.push(evidence('shared resource identifier(s)', present.join(', ')));
          }
          for (const note of diff.notes) ev.push(evidence('note', note));
          const prov = provenanceOf(ctx.graphs, sourceReq.id);
          if (prov) ev.push(evidence('discovery action', prov));

          findings.push({
            id: `${this.id}-${randomUUID().slice(0, 8)}`,
            type: this.id,
            title: `${testUser.name} can access ${sourceInv.user}'s resource at ${pathOf(sourceReq.url)}`,
            severity: present.length > 0 ? 'high' : 'medium',
            confidence,
            sourceUser: sourceInv.user,
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

  /** Confidence from the comparison verdict and marker confirmation. */
  private scoreConfidence(
    verdict: string,
    markerCount: number,
    presentCount: number,
  ): Confidence | undefined {
    if (presentCount > 0) return 'high'; // same object id echoed back to the peer
    if (verdict === 'identical') return markerCount === 0 ? 'medium' : 'high';
    if (verdict === 'access-granted') return 'medium';
    return undefined;
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
