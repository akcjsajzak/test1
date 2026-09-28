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
import type { Confidence, Evidence, Finding, Severity } from '../core/types';
import { compareResponses } from './compare';
import {
  evidence,
  isDataBearingResource,
  isObjectRefRequest,
  markersPresent,
  pickRepresentative,
  privilegeOf,
  provenanceOf,
  replayResponse,
  resourceMarkers,
  resourceTenantScoped,
  snapshotObserved,
  snapshotReplay,
  sourceResponse,
} from './authz-common';

/** Placeholders that indicate an object-referencing (per-resource) endpoint. */
export class HorizontalAnalyzer implements Analyzer {
  readonly id = 'AUTHZ-HORIZONTAL';
  readonly title = 'Horizontal authorization (object-level / IDOR)';

  async analyze(ctx: AnalysisContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const privileges = new Map(ctx.users.map((u) => [u.name, privilegeOf(u)]));
    const tenants = new Map(ctx.users.map((u) => [u.name, u.tenant]));

    for (const sourceInv of ctx.inventory.allUsers()) {
      const sourcePriv = privileges.get(sourceInv.user) ?? 10;
      for (const [signature, obs] of sourceInv.endpoints) {
        const sourceReq = pickRepresentative(ctx.requestsById, obs.requestIds);
        if (!sourceReq || sourceReq.status === undefined || sourceReq.status < 200 || sourceReq.status >= 300) {
          continue; // need a successful baseline
        }
        // Only object-referencing endpoints (path id, or a GraphQL op with variables).
        if (!isObjectRefRequest(sourceReq, signature)) continue;
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

          // Tenant-aware severity: elevate cross-tenant, de-prioritize same-tenant
          // access to a tenant-scoped resource (likely legitimate sharing).
          let severity: Severity = present.length > 0 ? 'high' : 'medium';
          let finalConfidence = confidence;
          const tags = this.tenantAdjust(
            tenants.get(sourceInv.user),
            tenants.get(testUser.name),
            sourceReq.url,
            ev,
            (s, c) => { severity = s; finalConfidence = c ?? finalConfidence; },
          );

          findings.push({
            id: `${this.id}-${randomUUID().slice(0, 8)}`,
            type: this.id,
            title: `${testUser.name} can access ${sourceInv.user}'s resource at ${pathOf(sourceReq.url)}`,
            severity,
            confidence: finalConfidence,
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
            tags: tags.length ? tags : undefined,
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

  /**
   * Apply tenant-aware severity/confidence. Only active when both users declare a
   * tenant. Cross-tenant is elevated; same-tenant access to a tenant-scoped
   * resource is de-prioritized (likely legitimate sharing); same-tenant access to
   * a per-user resource stays as scored. Returns the tags to attach.
   */
  private tenantAdjust(
    sourceTenant: string | number | undefined,
    testTenant: string | number | undefined,
    url: string,
    ev: Evidence[],
    set: (severity: Severity, confidence?: Confidence) => void,
  ): string[] {
    if (sourceTenant === undefined || testTenant === undefined) return [];
    const s = String(sourceTenant);
    const t = String(testTenant);
    if (s !== t) {
      ev.push(evidence('tenant boundary', `CROSSED — ${t}-tenant context reached a resource seen in tenant ${s}`));
      set('high', 'high');
      return ['cross-tenant'];
    }
    if (resourceTenantScoped(url, s)) {
      ev.push(evidence('tenant boundary', `same tenant (${s}); tenant-scoped resource — likely legitimate intra-tenant sharing, verify`));
      set('info', 'low');
      return ['same-tenant-shared'];
    }
    ev.push(evidence('tenant boundary', `same tenant (${s}); per-user resource — cross-user access is still a finding`));
    return ['same-tenant'];
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
