import { describe, it, expect } from 'vitest';
import { substituteEnv, validateConfig, ConfigError } from '../../src/config/loader';

describe('substituteEnv', () => {
  it('replaces ${VAR} from the environment', () => {
    const out = substituteEnv({ v: '${TOK}' }, { TOK: 'secret' } as NodeJS.ProcessEnv);
    expect(out).toEqual({ v: 'secret' });
  });
  it('uses defaults when the var is missing', () => {
    const out = substituteEnv('${MISSING:-fallback}', {} as NodeJS.ProcessEnv);
    expect(out).toBe('fallback');
  });
  it('throws when a required var is missing', () => {
    expect(() => substituteEnv('${MUST_SET}', {} as NodeJS.ProcessEnv)).toThrow(ConfigError);
  });
  it('recurses into arrays and objects', () => {
    const out = substituteEnv({ a: ['${X}', { b: '${X}' }] }, { X: '1' } as NodeJS.ProcessEnv);
    expect(out).toEqual({ a: ['1', { b: '1' }] });
  });
});

describe('validateConfig', () => {
  const base = {
    authorizedTesting: true,
    target: { url: 'https://app.test/' },
    users: [{ name: 'u', cookies: [{ name: 's', value: 'v' }] }],
  };

  it('accepts a minimal valid config and applies defaults', () => {
    const cfg = validateConfig(base);
    expect(cfg.crawl.maxDepth).toBeGreaterThan(0);
    expect(cfg.replay.allowedMethods).toContain('GET');
    expect(cfg.replay.allowDestructive).toBe(false);
  });

  it('defaults authorizedTesting to false when omitted', () => {
    const cfg = validateConfig({ target: base.target, users: base.users });
    expect(cfg.authorizedTesting).toBe(false);
  });

  it('rejects a config without users', () => {
    expect(() => validateConfig({ authorizedTesting: true, target: base.target, users: [] })).toThrow(
      ConfigError,
    );
  });

  it('rejects an invalid target URL', () => {
    expect(() => validateConfig({ ...base, target: { url: 'not-a-url' } })).toThrow(ConfigError);
  });
});
