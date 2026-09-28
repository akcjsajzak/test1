/**
 * Structured logging built on pino.
 *
 * The logger is configured with a redaction paths list so that even if a
 * secret-bearing object is accidentally logged, common sensitive keys are
 * masked. Application code should still avoid passing raw secrets, but this is
 * a defense-in-depth backstop.
 */
import pino, { type Logger, type LoggerOptions } from 'pino';

export type { Logger };

const REDACT_PATHS = [
  'cookie',
  'cookies',
  'Cookie',
  'authorization',
  'Authorization',
  'set-cookie',
  'token',
  'secret',
  'password',
  '*.cookie',
  '*.authorization',
  '*.token',
  'headers.cookie',
  'headers.authorization',
  'headers.Authorization',
];

export interface LoggerConfig {
  level?: string;
  /** pretty-print for humans (dev), otherwise NDJSON. */
  pretty?: boolean;
  /** write logs to this file (NDJSON) in addition to stderr, if set. */
  file?: string;
}

/**
 * Create a configured root logger. Structured NDJSON by default; pretty output
 * when `pretty` is set and pino-pretty is installed.
 */
export function createLogger(config: LoggerConfig = {}): Logger {
  const level = config.level ?? process.env.LOG_LEVEL ?? 'info';
  const options: LoggerOptions = {
    level,
    redact: {
      paths: REDACT_PATHS,
      censor: '[REDACTED]',
    },
    base: undefined, // omit pid/hostname noise
    timestamp: pino.stdTimeFunctions.isoTime,
  };

  const targets: any[] = [];
  if (config.pretty) {
    targets.push({
      target: 'pino-pretty',
      level,
      options: { colorize: true, translateTime: 'SYS:standard', ignore: 'pid,hostname' },
    });
  } else {
    targets.push({ target: 'pino/file', level, options: { destination: 2 } }); // stderr
  }
  if (config.file) {
    targets.push({ target: 'pino/file', level, options: { destination: config.file, mkdir: true } });
  }

  try {
    return pino(options, pino.transport({ targets }));
  } catch {
    // Fallback if transport worker cannot start (e.g. pino-pretty missing).
    return pino(options);
  }
}

/** A no-op logger for tests / library embedding. */
export function silentLogger(): Logger {
  return pino({ level: 'silent' });
}
