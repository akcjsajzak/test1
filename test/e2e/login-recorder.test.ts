import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { start } from '../../test-app-enterprise/server.js';
import { validateConfig } from '../../src/config/loader';
import { silentLogger } from '../../src/core/logger';
import { recordLogins } from '../../src/orchestrator/record-login';

let server: { close: () => void };
let baseUrl: string;

beforeAll(async () => {
  const started = await start(0);
  server = started.server;
  baseUrl = `http://127.0.0.1:${started.port}/`;
});

afterAll(() => server?.close());

describe('login recorder', () => {
  it(
    'runs a scripted login and captures the resulting session cookie',
    async () => {
      const config = validateConfig({
        authorizedTesting: true,
        target: { url: baseUrl },
        users: [
          {
            name: 'alice',
            role: 'member',
            login: {
              url: `${baseUrl}login`,
              steps: [
                { fill: '#email', value: 'alice@acme.test' },
                { fill: '#password', value: 'password' },
                { click: '#login-submit' },
                { waitForUrl: '/dashboard' },
              ],
              successUrlIncludes: '/dashboard',
            },
          },
        ],
      });

      const results = await recordLogins(config, silentLogger());
      expect(results).toHaveLength(1);
      expect(results[0].ok).toBe(true);
      const session = results[0].cookies?.find((c) => c.name === 'session');
      expect(session?.value).toBe('tok_alice');
    },
    90000,
  );

  it(
    'reports a login failure clearly (wrong password)',
    async () => {
      const config = validateConfig({
        authorizedTesting: true,
        target: { url: baseUrl },
        users: [
          {
            name: 'bad',
            role: 'member',
            login: {
              url: `${baseUrl}login`,
              steps: [
                { fill: '#email', value: 'alice@acme.test' },
                { fill: '#password', value: 'wrong' },
                { click: '#login-submit' },
                { waitForUrl: '/dashboard' },
              ],
              successUrlIncludes: '/dashboard',
            },
          },
        ],
      });
      const results = await recordLogins(config, silentLogger());
      expect(results[0].ok).toBe(false);
      expect(results[0].error).toBeTruthy();
    },
    90000,
  );
});
