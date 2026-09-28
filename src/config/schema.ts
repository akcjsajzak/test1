/**
 * Configuration schema (Zod) for the auditor.
 *
 * A single YAML/JSON document describes the target, the authenticated user
 * contexts, the proxy, the scope guard, crawl budgets, the replay policy and
 * reporting. Defaults are chosen to be safe: no destructive replay, tight
 * budgets, scope limited to the target host.
 */
import { z } from 'zod';

export const cookieSchema = z.object({
  name: z.string().min(1),
  value: z.string(),
  domain: z.string().optional(),
  path: z.string().default('/'),
  httpOnly: z.boolean().optional(),
  secure: z.boolean().optional(),
  sameSite: z.enum(['Strict', 'Lax', 'None']).optional(),
});

export const headerSchema = z.object({
  name: z.string().min(1),
  value: z.string(),
});

export const userSchema = z.object({
  /** logical identifier, e.g. user_a, admin. */
  name: z.string().min(1),
  /** expected role label, used for reporting. */
  role: z.string().optional(),
  /**
   * privilege level (higher = more privileged). Used by the vertical analyzer
   * to know which contexts should be "less privileged". anonymous=0.
   */
  privilegeLevel: z.number().int().min(0).optional(),
  /**
   * Optional tenant/org identifier. When set on the users involved, the
   * horizontal analyzer elevates cross-tenant access and de-prioritizes
   * same-tenant access to tenant-scoped resources (likely legitimate sharing).
   */
  tenant: z.union([z.string(), z.number()]).optional(),
  cookies: z.array(cookieSchema).default([]),
  headers: z.array(headerSchema).default([]),
  /** localStorage entries to seed into the isolated context (origin-scoped). */
  localStorage: z.array(z.object({ name: z.string(), value: z.string() })).default([]),
});

export const proxySchema = z.object({
  type: z.enum(['http', 'https', 'socks5', 'socks4']),
  url: z.string().min(1),
  username: z.string().optional(),
  password: z.string().optional(),
});

export const scopeSchema = z.object({
  /** hostnames that may be requested. The target host is always allowed. */
  allowedDomains: z.array(z.string()).default([]),
  /** when true, subdomains of allowed domains are also in scope. */
  allowSubdomains: z.boolean().default(true),
  /** hostnames that must never be requested (wins over allow). */
  deniedDomains: z.array(z.string()).default([]),
  /** CIDR ranges (IPv4) that must never be requested. */
  deniedIpRanges: z.array(z.string()).default([
    '127.0.0.0/8',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '169.254.0.0/16',
  ]),
  /** analytics/tracking hosts excluded from analysis (still allowed to load). */
  excludeHosts: z.array(z.string()).default([
    'google-analytics.com',
    'googletagmanager.com',
    'doubleclick.net',
    'facebook.com',
    'segment.io',
    'sentry.io',
    'hotjar.com',
    'mixpanel.com',
  ]),
  /** URL substrings excluded from analysis (tracking pixels, telemetry). */
  excludeUrlPatterns: z.array(z.string()).default(['/analytics', '/telemetry', '/collect', '/beacon']),
  maxRequests: z.number().int().positive().default(2000),
  maxDurationSeconds: z.number().int().positive().default(600),
  /** soft rate limit applied to crawling and replay. */
  requestsPerSecond: z.number().positive().default(8),
});

export const crawlSchema = z.object({
  maxDepth: z.number().int().min(0).default(3),
  maxPages: z.number().int().positive().default(60),
  maxActions: z.number().int().positive().default(400),
  maxRequests: z.number().int().positive().default(1500),
  maxDurationSeconds: z.number().int().positive().default(300),
  /** whether to trigger interactive elements (buttons, tabs, menus). */
  interact: z.boolean().default(true),
  /** whether to submit forms (kept off by default; can mutate state). */
  submitForms: z.boolean().default(false),
  /** allow interactions classified as potentially destructive. Default false. */
  includeDestructive: z.boolean().default(false),
  /** ms to wait after each interaction for async work to settle. */
  settleMs: z.number().int().min(0).default(400),
});

export const replaySchema = z.object({
  enabled: z.boolean().default(true),
  /** HTTP methods eligible for cross-context replay. */
  allowedMethods: z.array(z.string()).default(['GET', 'HEAD', 'OPTIONS']),
  /** allow replay of mutating methods (POST/PUT/PATCH/DELETE). Default false. */
  allowDestructive: z.boolean().default(false),
  maxReplays: z.number().int().positive().default(500),
});

export const idorSchema = z.object({
  /**
   * Active IDOR / enumeration probing. Off by default because it issues new
   * (constructed) requests beyond what was observed; enable it deliberately.
   */
  enabled: z.boolean().default(false),
  /** probe id-n .. id+n around each observed numeric id. */
  numericNeighbors: z.number().int().min(0).default(3),
  /** cap probes per endpoint template. */
  maxProbesPerEndpoint: z.number().int().positive().default(8),
  /** global cap on enumeration probes across the scan. */
  maxTotalProbes: z.number().int().positive().default(200),
});

export const compareSchema = z.object({
  /** JSON field names ignored when diffing (dynamic values). */
  ignoreFields: z.array(z.string()).default([
    'csrf',
    'csrfToken',
    'xsrf',
    '_token',
    'timestamp',
    'ts',
    'time',
    'date',
    'nonce',
    'requestId',
    'request_id',
    'traceId',
    'trace_id',
    'sessionId',
    'etag',
    'lastModified',
  ]),
  /** response headers ignored when diffing. */
  ignoreHeaders: z.array(z.string()).default([
    'date',
    'set-cookie',
    'etag',
    'last-modified',
    'x-request-id',
    'x-trace-id',
    'cf-ray',
    'age',
    'expires',
  ]),
});

export const browserSchema = z.object({
  headless: z.boolean().default(true),
  /** path to the Chromium executable; auto-detected when omitted. */
  executablePath: z.string().optional(),
  extraArgs: z.array(z.string()).default([]),
  navigationTimeoutMs: z.number().int().positive().default(20000),
  /** user agent override, if any. */
  userAgent: z.string().optional(),
});

export const outputSchema = z.object({
  dir: z.string().default('./results'),
  formats: z.array(z.enum(['json', 'html'])).default(['json', 'html']),
});

export const configSchema = z.object({
  /**
   * Explicit acknowledgement that the operator is authorized to test the
   * target. The scanner refuses to run unless this is true.
   */
  authorizedTesting: z.boolean().default(false),
  target: z.object({
    url: z.string().url(),
  }),
  users: z.array(userSchema).min(1),
  proxy: proxySchema.optional(),
  scope: scopeSchema.default({}),
  crawl: crawlSchema.default({}),
  replay: replaySchema.default({}),
  idor: idorSchema.default({}),
  compare: compareSchema.default({}),
  browser: browserSchema.default({}),
  output: outputSchema.default({}),
});

export type Config = z.infer<typeof configSchema>;
export type UserSpec = z.infer<typeof userSchema>;
export type CookieSpec = z.infer<typeof cookieSchema>;
export type ProxySpec = z.infer<typeof proxySchema>;
export type ScopeSpec = z.infer<typeof scopeSchema>;
export type CrawlSpec = z.infer<typeof crawlSchema>;
export type ReplaySpec = z.infer<typeof replaySchema>;
export type IdorSpec = z.infer<typeof idorSchema>;
export type CompareSpec = z.infer<typeof compareSchema>;
export type BrowserSpec = z.infer<typeof browserSchema>;
export type OutputSpec = z.infer<typeof outputSchema>;
