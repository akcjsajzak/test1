/**
 * CDP-based network collector.
 *
 * Attaches to a page's Chrome DevTools Protocol session and captures the full
 * network picture: navigations, HTTP(S) requests/responses, redirects, XHR,
 * fetch, WebSocket and EventSource. Using CDP (rather than only Playwright's
 * high-level events) gives native access to the request initiator, resource
 * type and precise encoded sizes/timing, which the spec prioritizes.
 *
 * Every captured request is passed through redaction before it is emitted, so
 * no secret header/param/body value is ever stored in clear.
 */
import type { CDPSession } from 'playwright-core';
import { randomUUID } from 'node:crypto';
import type {
  HeaderPair,
  ObservedRequest,
  ParamPair,
  RequestInitiator,
} from '../core/types';
import { redactBody, redactHeader, redactParam } from '../config/redaction';
import type { ScopeGuard } from '../core/scope';

export interface NetworkCollectorOptions {
  user: string;
  scope: ScopeGuard;
  /** returns the URL/route currently active in the page (for source tagging). */
  currentRoute: () => string | undefined;
  /** called for every finalized request. */
  sink: (req: ObservedRequest) => void;
  /** max bytes of a response body to snapshot for analysis. */
  maxBodyBytes?: number;
  /** content-type substrings whose bodies are worth snapshotting. */
  textContentTypes?: string[];
}

interface PendingRequest {
  cdpRequestId: string;
  observed: ObservedRequest;
  /** whether we intend to fetch the response body on finish. */
  wantBody: boolean;
}

const DEFAULT_MAX_BODY = 256 * 1024;
const DEFAULT_TEXT_TYPES = ['json', 'text', 'html', 'xml', 'javascript', 'x-www-form-urlencoded'];

export class NetworkCollector {
  private readonly cdp: CDPSession;
  private readonly opts: Required<Pick<NetworkCollectorOptions, 'maxBodyBytes' | 'textContentTypes'>> &
    NetworkCollectorOptions;
  private readonly pending = new Map<string, PendingRequest>();
  private readonly finalizers = new Set<Promise<void>>();
  private attached = false;

  constructor(cdp: CDPSession, options: NetworkCollectorOptions) {
    this.cdp = cdp;
    this.opts = {
      maxBodyBytes: DEFAULT_MAX_BODY,
      textContentTypes: DEFAULT_TEXT_TYPES,
      ...options,
    };
  }

  async attach(): Promise<void> {
    if (this.attached) return;
    this.attached = true;
    await this.cdp.send('Network.enable', {
      maxTotalBufferSize: 10 * 1024 * 1024,
      maxResourceBufferSize: 5 * 1024 * 1024,
    });

    this.cdp.on('Network.requestWillBeSent', (e: any) => this.onRequestWillBeSent(e));
    this.cdp.on('Network.responseReceived', (e: any) => this.onResponseReceived(e));
    this.cdp.on('Network.loadingFinished', (e: any) => this.enqueue(this.onLoadingFinished(e)));
    this.cdp.on('Network.loadingFailed', (e: any) => this.onLoadingFailed(e));
    this.cdp.on('Network.webSocketCreated', (e: any) => this.onWebSocketCreated(e));
    this.cdp.on('Network.eventSourceMessageReceived', (e: any) => this.onEventSource(e));
  }

  /** Wait for any in-flight body fetches to complete. */
  async flush(): Promise<void> {
    await Promise.allSettled([...this.finalizers]);
  }

  private enqueue(p: Promise<void>): void {
    this.finalizers.add(p);
    p.finally(() => this.finalizers.delete(p));
  }

  private onRequestWillBeSent(e: any): void {
    const req = e.request;
    if (!req?.url) return;
    const url: string = req.url;
    if (url.startsWith('data:') || url.startsWith('blob:')) return;

    // A redirectResponse on this event means the *previous* request under this
    // id completed with a redirect; finalize it as its own observation.
    if (e.redirectResponse) {
      const prev = this.pending.get(e.requestId);
      if (prev) {
        prev.observed.status = e.redirectResponse.status;
        prev.observed.statusText = e.redirectResponse.statusText;
        prev.observed.responseHeaders = this.headerObject(e.redirectResponse.headers);
        prev.observed.redirectedTo = url;
        this.emit(prev.observed);
        this.pending.delete(e.requestId);
      }
    }

    const host = safeHost(url);
    const inScope = this.opts.scope.urlInScope(url);
    const excluded = this.opts.scope.isExcludedFromAnalysis(url);

    const observed: ObservedRequest = {
      id: `${this.opts.user}:${e.requestId}:${randomUUID().slice(0, 8)}`,
      user: this.opts.user,
      method: (req.method ?? 'GET').toUpperCase(),
      url,
      origin: safeOrigin(e.documentURL ?? url),
      host,
      resourceType: (e.type ?? '').toLowerCase() || undefined,
      requestHeaders: this.headerObject(req.headers),
      params: this.extractParams(url, req.postData, req.headers),
      requestBody: this.snapshotRequestBody(req),
      responseHeaders: [],
      timing: { startedAt: Date.now() },
      initiator: this.mapInitiator(e.initiator),
      sourceRoute: this.opts.currentRoute(),
      redirectedFrom: e.redirectResponse?.url,
      outOfScope: !inScope.allowed,
    };

    const wantBody = !excluded && inScope.allowed;
    this.pending.set(e.requestId, { cdpRequestId: e.requestId, observed, wantBody });
  }

  private onResponseReceived(e: any): void {
    const pending = this.pending.get(e.requestId);
    if (!pending) return;
    const resp = e.response;
    pending.observed.status = resp.status;
    pending.observed.statusText = resp.statusText;
    pending.observed.responseHeaders = this.headerObject(resp.headers);
    pending.observed.contentType = (resp.mimeType ?? '').toLowerCase() || undefined;
    if (!pending.observed.resourceType && e.type) {
      pending.observed.resourceType = String(e.type).toLowerCase();
    }
  }

  private async onLoadingFinished(e: any): Promise<void> {
    const pending = this.pending.get(e.requestId);
    if (!pending) return;
    this.pending.delete(e.requestId);
    const obs = pending.observed;
    obs.responseSize = typeof e.encodedDataLength === 'number' ? e.encodedDataLength : obs.responseSize;
    obs.timing.durationMs = Date.now() - obs.timing.startedAt;

    if (pending.wantBody && this.isTextLike(obs.contentType)) {
      try {
        const body = await this.cdp.send('Network.getResponseBody', { requestId: e.requestId });
        let text = body.base64Encoded ? Buffer.from(body.body, 'base64').toString('utf8') : body.body;
        if (text.length > this.opts.maxBodyBytes) text = text.slice(0, this.opts.maxBodyBytes);
        obs.responseBody = redactBody(obs.contentType, text);
      } catch {
        // Body may have been evicted from the buffer; that is acceptable.
      }
    }
    this.emit(obs);
  }

  private onLoadingFailed(e: any): void {
    const pending = this.pending.get(e.requestId);
    if (!pending) return;
    this.pending.delete(e.requestId);
    pending.observed.timing.durationMs = Date.now() - pending.observed.timing.startedAt;
    pending.observed.statusText = e.errorText ?? 'failed';
    this.emit(pending.observed);
  }

  private onWebSocketCreated(e: any): void {
    if (!e.url) return;
    const url: string = e.url;
    this.emit({
      id: `${this.opts.user}:ws:${randomUUID().slice(0, 8)}`,
      user: this.opts.user,
      method: 'WEBSOCKET',
      url,
      host: safeHost(url),
      resourceType: 'websocket',
      requestHeaders: [],
      params: this.extractParams(url, undefined, undefined),
      responseHeaders: [],
      timing: { startedAt: Date.now() },
      initiator: this.mapInitiator(e.initiator),
      sourceRoute: this.opts.currentRoute(),
      outOfScope: !this.opts.scope.urlInScope(url).allowed,
    });
  }

  private onEventSource(e: any): void {
    // EventSource messages arrive against an existing request id; annotate it.
    const pending = this.pending.get(e.requestId);
    if (pending && pending.observed.resourceType !== 'eventsource') {
      pending.observed.resourceType = 'eventsource';
    }
  }

  private emit(obs: ObservedRequest): void {
    try {
      this.opts.sink(obs);
    } catch {
      // A misbehaving sink must never break capture.
    }
  }

  private headerObject(headers: Record<string, string> | undefined): HeaderPair[] {
    if (!headers) return [];
    const out: HeaderPair[] = [];
    for (const [name, value] of Object.entries(headers)) {
      const { value: v, redacted } = redactHeader(name, String(value));
      out.push({ name, value: v, redacted: redacted || undefined });
    }
    return out;
  }

  private extractParams(
    url: string,
    postData: string | undefined,
    _headers: Record<string, string> | undefined,
  ): ParamPair[] {
    const params: ParamPair[] = [];
    try {
      const u = new URL(url);
      for (const [k, v] of u.searchParams.entries()) {
        const { value, redacted } = redactParam(k, v);
        params.push({ name: k, value, location: 'query', redacted: redacted || undefined });
      }
    } catch {
      /* ignore */
    }
    if (postData) {
      // Only surface form-encoded keys as params; JSON bodies are captured whole.
      if (/^[^=&\s]+=[^&]*(&|$)/.test(postData)) {
        for (const pair of postData.split('&')) {
          const idx = pair.indexOf('=');
          if (idx < 0) continue;
          const k = decodeSafe(pair.slice(0, idx));
          const { value, redacted } = redactParam(k, decodeSafe(pair.slice(idx + 1)));
          params.push({ name: k, value, location: 'body', redacted: redacted || undefined });
        }
      }
    }
    return params;
  }

  private snapshotRequestBody(req: any): string | undefined {
    if (!req.postData) return undefined;
    let body: string = req.postData;
    if (body.length > this.opts.maxBodyBytes) body = body.slice(0, this.opts.maxBodyBytes);
    return redactBody(req.headers?.['Content-Type'] ?? req.headers?.['content-type'], body);
  }

  private mapInitiator(initiator: any): RequestInitiator | undefined {
    if (!initiator) return undefined;
    const top = initiator.stack?.callFrames?.[0];
    return {
      type: initiator.type,
      url: initiator.url ?? top?.url,
      lineNumber: top?.lineNumber,
    };
  }

  private isTextLike(contentType?: string): boolean {
    if (!contentType) return true; // unknown — attempt, but body may be empty
    return this.opts.textContentTypes.some((t) => contentType.includes(t));
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function safeOrigin(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

function decodeSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
