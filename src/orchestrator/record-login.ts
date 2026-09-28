/**
 * Login recorder: run each user's scripted login and capture the resulting
 * session (cookies), so operators don't have to hand-extract cookies from a
 * browser. Credentials come from the config's login steps (typically via env
 * vars) and are never logged; only the captured cookies are returned.
 */
import { BrowserEngine } from '../browser/engine';
import { ScopeGuard } from '../core/scope';
import type { Config } from '../config/schema';
import type { Logger } from '../core/logger';

export interface RecordedSession {
  user: string;
  ok: boolean;
  error?: string;
  cookies?: Array<{ name: string; value: string; domain: string; path: string }>;
}

export interface RecordLoginOptions {
  /** only record this user (by name). */
  onlyUser?: string;
}

/** Perform scripted logins for every user that declares a `login` block. */
export async function recordLogins(
  config: Config,
  logger: Logger,
  opts: RecordLoginOptions = {},
): Promise<RecordedSession[]> {
  const results: RecordedSession[] = [];
  const scope = new ScopeGuard(config.target.url, config.scope);
  const engine = new BrowserEngine({ browser: config.browser, proxy: config.proxy, logger });
  await engine.launch();
  try {
    for (const user of config.users) {
      if (!user.login) continue;
      if (opts.onlyUser && user.name !== opts.onlyUser) continue;
      let session;
      try {
        session = await engine.createSession(user, {
          targetUrl: config.target.url,
          navigationTimeoutMs: config.browser.navigationTimeoutMs,
          scope,
          sink: () => undefined, // no network analysis while recording
          logger,
        });
        await session.login(user.login);
        const state = await session.storageState();
        results.push({ user: user.name, ok: true, cookies: state.cookies });
      } catch (err) {
        results.push({ user: user.name, ok: false, error: (err as Error).message });
      } finally {
        await session?.close();
      }
    }
  } finally {
    await engine.close();
  }
  return results;
}
