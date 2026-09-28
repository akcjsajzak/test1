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
import type { LoginSpec, LoginStep, UserSpec } from '../config/schema';
import { NetworkCollector } from './network';

export class LoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LoginError';
  }
}

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

    // Hook client-side routing so SPA navigations (pushState/replaceState) are
    // observable to the crawler, which polls window.__aa_routes.
    await this.context.addInitScript(() => {
      try {
        const w = window as unknown as { __aa_routes?: string[] };
        w.__aa_routes = w.__aa_routes || [];
        const record = (url: unknown) => {
          try {
            if (url != null) w.__aa_routes!.push(new URL(String(url), location.href).href);
          } catch {
            /* ignore */
          }
        };
        const wrap =
          (orig: History['pushState']): History['pushState'] =>
          function (this: History, data: unknown, unused: string, url?: string | URL | null) {
            record(url);
            return orig.call(this, data, unused, url as string);
          };
        history.pushState = wrap(history.pushState);
        history.replaceState = wrap(history.replaceState);
      } catch {
        /* ignore */
      }
    });

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

  /**
   * Run a scripted login to obtain a session. Step values may contain secrets
   * (passwords) injected from env vars; they are used to authenticate but never
   * logged. The resulting session lives in this isolated context.
   */
  async login(spec: LoginSpec): Promise<void> {
    const timeout = this.opts.navigationTimeoutMs;
    const start = spec.url ?? this.opts.targetUrl;
    await this.page.goto(start, { waitUntil: 'domcontentloaded' });
    for (const step of spec.steps) {
      await this.runLoginStep(step, timeout);
    }
    this.route = this.page.url();
    if (spec.successUrlIncludes && !this.page.url().includes(spec.successUrlIncludes)) {
      throw new LoginError(
        `login for ${this.name} did not reach the expected URL (wanted a URL containing "${spec.successUrlIncludes}", got "${this.page.url()}")`,
      );
    }
    this.opts.logger.info({ user: this.name, url: safeUrl(this.page.url()) }, 'login completed');
  }

  private async runLoginStep(step: LoginStep, timeout: number): Promise<void> {
    const p = this.page;
    try {
      if (step.goto) await p.goto(step.goto, { waitUntil: 'domcontentloaded' });
      if (step.fill) await p.fill(step.fill, step.value ?? '', { timeout });
      if (step.type) await p.locator(step.type).pressSequentially(step.value ?? '', { timeout });
      if (step.click) await p.click(step.click, { timeout });
      if (step.press) await p.keyboard.press(step.press);
      if (step.waitForSelector) await p.waitForSelector(step.waitForSelector, { timeout });
      if (step.waitForUrl) await p.waitForURL((u) => u.href.includes(step.waitForUrl as string), { timeout });
      if (step.waitFor) await p.waitForLoadState(step.waitFor, { timeout });
      if (step.waitMs) await p.waitForTimeout(step.waitMs);
    } catch (err) {
      throw new LoginError(`login step failed for ${this.name}: ${describeStep(step)} — ${(err as Error).message}`);
    }
  }

  /** Capture the current context's storage state (cookies + localStorage). */
  async storageState(): Promise<{ cookies: Array<{ name: string; value: string; domain: string; path: string }> }> {
    const state = await this.context.storageState();
    return { cookies: state.cookies.map((c) => ({ name: c.name, value: c.value, domain: c.domain, path: c.path })) };
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

/** Describe a login step without leaking its value (which may be a password). */
function describeStep(step: LoginStep): string {
  if (step.goto) return `goto ${step.goto}`;
  if (step.fill) return `fill ${step.fill}`;
  if (step.type) return `type into ${step.type}`;
  if (step.click) return `click ${step.click}`;
  if (step.press) return `press ${step.press}`;
  if (step.waitForSelector) return `waitForSelector ${step.waitForSelector}`;
  if (step.waitForUrl) return `waitForUrl ${step.waitForUrl}`;
  if (step.waitFor) return `waitFor ${step.waitFor}`;
  if (step.waitMs) return `waitMs ${step.waitMs}`;
  return '(no-op step)';
}

function safeUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return '[url]';
  }
}
