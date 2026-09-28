/**
 * Config loading: read YAML or JSON, substitute environment variables, then
 * validate against the schema.
 *
 * Secrets (session cookies, tokens) should be referenced as ${ENV_VAR} in the
 * config file and injected at runtime, so the file itself carries no secrets.
 * Substitution supports ${VAR} and ${VAR:-default}.
 */
import { readFileSync } from 'node:fs';
import { extname } from 'node:path';
import yaml from 'js-yaml';
import { configSchema, type Config } from './schema';

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

const ENV_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g;

/**
 * Recursively substitute ${VAR} / ${VAR:-default} in all string values.
 * A missing variable with no default throws, so scans fail fast rather than
 * running with an empty session cookie.
 */
export function substituteEnv(value: unknown, env: NodeJS.ProcessEnv = process.env): unknown {
  if (typeof value === 'string') {
    return value.replace(ENV_PATTERN, (_m, name: string, dflt: string | undefined) => {
      const resolved = env[name];
      if (resolved !== undefined && resolved !== '') return resolved;
      if (dflt !== undefined) return dflt;
      throw new ConfigError(
        `Environment variable ${name} is required by the config but is not set (and no default given).`,
      );
    });
  }
  if (Array.isArray(value)) {
    return value.map((v) => substituteEnv(v, env));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = substituteEnv(v, env);
    }
    return out;
  }
  return value;
}

/** Parse a raw config document (YAML or JSON) into a plain object. */
export function parseRaw(text: string, filename: string): unknown {
  const ext = extname(filename).toLowerCase();
  if (ext === '.json') {
    return JSON.parse(text);
  }
  // js-yaml also parses JSON, so default to YAML for .yaml/.yml/unknown.
  return yaml.load(text);
}

/** Load, substitute env vars, and validate a config file. */
export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): Config {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new ConfigError(`Cannot read config file ${path}: ${(e as Error).message}`);
  }

  let raw: unknown;
  try {
    raw = parseRaw(text, path);
  } catch (e) {
    throw new ConfigError(`Cannot parse config file ${path}: ${(e as Error).message}`);
  }

  const substituted = substituteEnv(raw, env);
  const result = configSchema.safeParse(substituted);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ConfigError(`Config validation failed for ${path}:\n${issues}`);
  }
  return result.data;
}

/** Validate an already-parsed object (used by tests). */
export function validateConfig(obj: unknown): Config {
  const result = configSchema.safeParse(obj);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ConfigError(`Config validation failed:\n${issues}`);
  }
  return result.data;
}
