/**
 * Browser engine: launches Chromium and mints isolated per-user sessions.
 *
 * The executable is auto-detected so the tool runs against a pre-installed
 * Chromium (common on locked-down Debian hosts) without downloading anything.
 * Each user session is created from a fresh BrowserContext for hard isolation.
 *
 * Proxy notes / limitations (documented per the spec):
 *  - HTTP/HTTPS proxies work fully for browser traffic.
 *  - SOCKS5: Chromium honors SOCKS5 for TCP but does NOT support SOCKS proxy
 *    authentication, and by default resolves DNS locally (not over the proxy).
 *    Use an upstream that accepts unauthenticated local connections, or chain
 *    through a local forwarder, when anonymity of DNS matters.
 *  - The in-app replay engine uses Node's fetch, which honors the same proxy
 *    settings via undici when configured; see replay.ts.
 */
import { existsSync } from 'node:fs';
import { chromium, type Browser } from 'playwright-core';
import type { BrowserSpec, ProxySpec, UserSpec } from '../config/schema';
import type { Logger } from '../core/logger';
import type { ObservedRequest } from '../core/types';
import { UserSession, type UserSessionOptions } from './session';

const COMMON_CHROMIUM_PATHS = [
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE,
  process.env.CHROMIUM_PATH,
  '/opt/pw-browsers/chromium',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
];

export interface EngineLaunchOptions {
  browser: BrowserSpec;
  proxy?: ProxySpec;
  logger: Logger;
}

export class BrowserEngine {
  private browser?: Browser;
  private readonly opts: EngineLaunchOptions;

  constructor(opts: EngineLaunchOptions) {
    this.opts = opts;
  }

  /** Resolve a Chromium executable path, or undefined to let Playwright decide. */
  static detectExecutable(configured?: string): string | undefined {
    if (configured && existsSync(configured)) return configured;
    for (const p of COMMON_CHROMIUM_PATHS) {
      if (p && existsSync(p)) return p;
    }
    return undefined;
  }

  async launch(): Promise<void> {
    const executablePath = BrowserEngine.detectExecutable(this.opts.browser.executablePath);
    const args = [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-features=IsolateOrigins,site-per-process',
      ...this.opts.browser.extraArgs,
    ];
    this.opts.logger.info(
      { executablePath: executablePath ?? '(playwright default)', headless: this.opts.browser.headless },
      'launching Chromium',
    );
    this.browser = await chromium.launch({
      executablePath,
      headless: this.opts.browser.headless,
      args,
      proxy: this.opts.proxy ? { server: this.opts.proxy.url } : undefined,
    });
  }

  /** Create an isolated session for one user. */
  async createSession(
    user: UserSpec,
    sessionOpts: Omit<UserSessionOptions, 'sink'> & { sink: (req: ObservedRequest) => void },
  ): Promise<UserSession> {
    if (!this.browser) throw new Error('BrowserEngine.launch() must be called first');
    const context = await this.browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent: this.opts.browser.userAgent,
      // A dedicated context guarantees cookie/storage/cache isolation.
      proxy: this.opts.proxy
        ? {
            server: this.opts.proxy.url,
            username: this.opts.proxy.username,
            password: this.opts.proxy.password,
          }
        : undefined,
    });
    const session = new UserSession(context, user, sessionOpts);
    await session.init();
    return session;
  }

  async close(): Promise<void> {
    await this.browser?.close().catch(() => undefined);
    this.browser = undefined;
  }
}
