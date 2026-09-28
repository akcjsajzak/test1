/**
 * Controlled cross-context replay engine.
 *
 * Replays a previously observed request under a *different* user's context to
 * test whether that user can reach the same resource. Safety is central:
 *
 *  - The request is issued through the target user's own isolated browser
 *    context (via Playwright's APIRequestContext), so it carries that user's
 *    real session cookies. The source user's secret headers (Cookie,
 *    Authorization, …) are NEVER forwarded — that would both leak secrets and
 *    invalidate the test.
 *  - By default only safe, non-mutating methods (GET/HEAD/OPTIONS) are replayed.
 *    Mutating methods require an explicit opt-in and are otherwise skipped.
 *  - The target URL must be in scope; out-of-scope URLs are never replayed.
 *  - A global replay budget bounds the load placed on the application.
 */
import type { APIRequestContext } from 'playwright-core';
import type { Logger } from '../core/logger';
import type { ScopeGuard } from '../core/scope';
import type { ReplaySpec } from '../config/schema';
import type { HeaderPair, ObservedRequest, ReplayResult } from '../core/types';
import type { Replayer } from './engine';
import { redactBody, redactHeader } from '../config/redaction';

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
/** Headers we never forward from the source request. */
const FORBIDDEN_FORWARD_HEADERS = new Set([
  'cookie',
  'authorization',
  'proxy-authorization',
  'host',
  'content-length',
  'connection',
  'x-csrf-token',
  'x-xsrf-token',
  'authentication',
  ':method',
  ':path',
  ':authority',
  ':scheme',
]);
const MAX_BODY = 256 * 1024;

export interface ReplayEngineOptions {
  spec: ReplaySpec;
  scope: ScopeGuard;
  logger: Logger;
  /** returns the APIRequestContext bound to a user's isolated browser context. */
  requestContextFor: (user: string) => APIRequestContext | undefined;
}

export class ReplayEngine implements Replayer {
  private readonly opts: ReplayEngineOptions;
  private replaysUsed = 0;

  constructor(opts: ReplayEngineOptions) {
    this.opts = opts;
  }

  count(): number {
    return this.replaysUsed;
  }

  private policyCheck(request: ObservedRequest): { ok: boolean; reason?: string } {
    if (!this.opts.spec.enabled) return { ok: false, reason: 'replay disabled by config' };
    if (this.replaysUsed >= this.opts.spec.maxReplays) return { ok: false, reason: 'replay budget exhausted' };
    const method = request.method.toUpperCase();
    if (method === 'WEBSOCKET') return { ok: false, reason: 'websocket replay not supported' };

    const scopeDecision = this.opts.scope.urlInScope(request.url);
    if (!scopeDecision.allowed) return { ok: false, reason: `out of scope: ${scopeDecision.reason}` };

    // GraphQL: queries are read-only (safe) even though they use POST; mutations
    // and subscriptions are gated by allowDestructive.
    if (request.graphql) {
      if (request.graphql.operationType === 'query') {
        if (!this.opts.spec.allowGraphqlQueries) return { ok: false, reason: 'graphql query replay disabled' };
        return { ok: true };
      }
      if (!this.opts.spec.allowDestructive) {
        return { ok: false, reason: `graphql ${request.graphql.operationType} skipped (allowDestructive is false)` };
      }
      return { ok: true };
    }

    if (!this.opts.spec.allowedMethods.map((m) => m.toUpperCase()).includes(method)) {
      return { ok: false, reason: `method ${method} not in replay allow-list` };
    }
    if (MUTATING_METHODS.has(method) && !this.opts.spec.allowDestructive) {
      return { ok: false, reason: `mutating method ${method} skipped (allowDestructive is false)` };
    }
    return { ok: true };
  }

  async replay(request: ObservedRequest, asUser: string): Promise<ReplayResult> {
    const base: ReplayResult = {
      originalRequestId: request.id,
      originalUser: request.user,
      replayUser: asUser,
      method: request.method.toUpperCase(),
      url: request.url,
      requested: false,
      timestamp: Date.now(),
    };

    const policy = this.policyCheck(request);
    if (!policy.ok) return { ...base, skippedReason: policy.reason };

    const ctx = this.opts.requestContextFor(asUser);
    if (!ctx) return { ...base, skippedReason: `no request context for user ${asUser}` };

    if (!this.opts.scope.tryConsumeRequest()) {
      return { ...base, skippedReason: 'request budget exhausted' };
    }
    await this.opts.scope.throttle();
    this.replaysUsed += 1;

    try {
      const headers = this.forwardableHeaders(request);
      const method = base.method;
      const options: {
        method: string;
        headers: Record<string, string>;
        maxRedirects: number;
        timeout: number;
        failOnStatusCode: boolean;
        data?: string;
      } = { method, headers, maxRedirects: 0, timeout: 15000, failOnStatusCode: false };
      // Forward the request body for body-bearing methods (needed for GraphQL,
      // whose operation + variables live in the POST body).
      if (method !== 'GET' && method !== 'HEAD' && request.requestBody) {
        options.data = request.requestBody;
        const hasCt = Object.keys(headers).some((k) => k.toLowerCase() === 'content-type');
        if (!hasCt) headers['Content-Type'] = request.graphql ? 'application/json' : 'application/octet-stream';
      }
      const resp = await ctx.fetch(request.url, options);
      const status = resp.status();
      const respHeaders = resp.headers();
      let bodyText = '';
      try {
        bodyText = await resp.text();
      } catch {
        /* binary or empty */
      }
      if (bodyText.length > MAX_BODY) bodyText = bodyText.slice(0, MAX_BODY);
      const contentType = respHeaders['content-type'];

      return {
        ...base,
        requested: true,
        status,
        responseSize: bodyText.length,
        responseBody: redactBody(contentType, bodyText),
        contentType,
        responseHeaders: this.redactHeaders(respHeaders),
      };
    } catch (err) {
      this.opts.logger.debug(
        { url: request.url, asUser, err: (err as Error).message },
        'replay request failed',
      );
      return { ...base, requested: true, skippedReason: `replay error: ${(err as Error).message}` };
    }
  }

  /** Forward only non-sensitive, non-hop-by-hop headers from the source request. */
  private forwardableHeaders(request: ObservedRequest): Record<string, string> {
    const out: Record<string, string> = {};
    for (const h of request.requestHeaders) {
      const name = h.name.toLowerCase();
      if (FORBIDDEN_FORWARD_HEADERS.has(name)) continue;
      if (name.startsWith(':')) continue;
      if (h.redacted) continue; // never forward anything that was redacted
      out[h.name] = h.value;
    }
    return out;
  }

  private redactHeaders(headers: Record<string, string>): HeaderPair[] {
    return Object.entries(headers).map(([name, value]) => {
      const { value: v, redacted } = redactHeader(name, value);
      return { name, value: v, redacted: redacted || undefined };
    });
  }
}
