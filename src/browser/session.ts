/**
 * A per-user browser session backed by an isolated Playwright BrowserContext.
 *
 * Each user gets its own context, which isolates cookies, localStorage,
 * sessionStorage and cache from every other user — a hard requirement so that
 * one authenticated session can never contaminate another. The session seeds
 * the configured cookies/headers/localStorage (the real secret values are used
 * to authenticate but are never persisted; only redacted copies are stored),
 * tracks the current route, and owns the network collector for its page.
 */
import type { BrowserContext, Page } from 'playwright-core';
import type { Logger } from '../core/logger';
import type { ScopeGuard } from '../core/scope';
import type { ObservedRequest } from '../core/types';
import type { UserSpec } from '../config/schema';
import { NetworkCollector } from './network';

export interface UserSessionOptions {
  targetUrl: string;
  navigationTimeoutMs: number;
  scope: ScopeGuard;
  sink: (req: ObservedRequest) => void;
  logger: Logger;
}

export class UserSession {
  readonly user: UserSpec;
  private readonly context: BrowserContext;
  private readonly opts: UserSessionOptions;
  private page!: Page;
  private collector!: NetworkCollector;
  private route: string | undefined;

  constructor(context: BrowserContext, user: UserSpec, opts: UserSessionOptions) {
    this.context = context;
    this.user = user;
    this.opts = opts;
  }

  get name(): string {
    return this.user.name;
  }

  currentRoute(): string | undefined {
    return this.route;
  }

  getPage(): Page {
    return this.page;
  }

  getContext(): BrowserContext {
    return this.context;
  }

  /** Seed auth material, wire capture, and open the first page. */
  async init(): Promise<void> {
    const target = new URL(this.opts.targetUrl);

    if (this.user.headers.length > 0) {
      const headers: Record<string, string> = {};
      for (const h of this.user.headers) headers[h.name] = h.value;
      await this.context.setExtraHTTPHeaders(headers);
    }

    if (this.user.cookies.length > 0) {
      await this.context.addCookies(
        this.user.cookies.map((c) => ({
          name: c.name,
          value: c.value,
          domain: c.domain ?? target.hostname,
          path: c.path ?? '/',
          httpOnly: c.httpOnly,
          secure: c.secure ?? target.protocol === 'https:',
          sameSite: c.sameSite,
        })),
      );
    }

    if (this.user.localStorage.length > 0) {
      const entries = this.user.localStorage.map((e) => [e.name, e.value] as const);
      await this.context.addInitScript((items: ReadonlyArray<readonly [string, string]>) => {
        try {
          for (const [k, v] of items) window.localStorage.setItem(k, v);
        } catch {
          /* storage may be unavailable on some origins */
        }
      }, entries);
    }

    this.page = await this.context.newPage();
    this.page.setDefaultNavigationTimeout(this.opts.navigationTimeoutMs);
    this.page.setDefaultTimeout(this.opts.navigationTimeoutMs);

    this.page.on('framenavigated', (frame) => {
      if (frame === this.page.mainFrame()) this.route = frame.url();
    });

    const cdp = await this.context.newCDPSession(this.page);
    this.collector = new NetworkCollector(cdp, {
      user: this.user.name,
      scope: this.opts.scope,
      currentRoute: () => this.route,
      sink: this.opts.sink,
    });
    await this.collector.attach();
  }

  /** Navigate the main page to a URL, tolerating benign navigation errors. */
  async goto(url: string): Promise<void> {
    try {
      await this.page.goto(url, { waitUntil: 'domcontentloaded' });
      this.route = this.page.url();
    } catch (err) {
      this.opts.logger.debug({ user: this.name, url, err: (err as Error).message }, 'navigation error');
    }
  }

  /** Ensure pending response-body fetches complete before analysis reads them. */
  async flush(): Promise<void> {
    await this.collector.flush();
  }

  async close(): Promise<void> {
    await this.flush();
    await this.context.close().catch(() => undefined);
  }
}
