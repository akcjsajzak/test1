/**
 * Scope guard: the safety boundary of the auditor.
 *
 * The guard decides which hosts may be navigated to and replayed against, which
 * requests are merely observed (third-party) versus analyzed, and enforces the
 * request/time budgets and a soft rate limit. The posture is default-deny: only
 * the explicit target host and configured allow-list are ever navigated or
 * replayed; discovered third-party or private-range hosts are recorded but never
 * attacked.
 */
import type { ScopeSpec } from '../config/schema';

export interface ScopeDecision {
  allowed: boolean;
  reason: string;
}

/** Parse "a.b.c.d/nn" into a numeric base+mask, or null if not IPv4 CIDR. */
function parseCidr(cidr: string): { base: number; mask: number } | null {
  const [addr, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!addr || Number.isNaN(bits) || bits < 0 || bits > 32) return null;
  const ip = ipv4ToInt(addr);
  if (ip === null) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (ip & mask) >>> 0, mask };
}

function ipv4ToInt(addr: string): number | null {
  const parts = addr.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!/^\d+$/.test(p) || n < 0 || n > 255) return null;
    value = (value << 8) | n;
  }
  return value >>> 0;
}

function isIpv4(host: string): boolean {
  return ipv4ToInt(host) !== null;
}

/** Suffix match honoring domain boundaries: "api.example.com" matches "example.com". */
function hostMatches(host: string, domain: string, allowSubdomains: boolean): boolean {
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  if (h === d) return true;
  if (allowSubdomains && h.endsWith(`.${d}`)) return true;
  return false;
}

export class ScopeGuard {
  private readonly targetHost: string;
  private readonly spec: ScopeSpec;
  private readonly deniedCidrs: Array<{ base: number; mask: number }>;
  private requestCount = 0;
  private readonly startedAt = Date.now();
  private lastRequestAt = 0;

  constructor(targetUrl: string, spec: ScopeSpec) {
    this.targetHost = new URL(targetUrl).hostname.toLowerCase();
    this.spec = spec;
    this.deniedCidrs = spec.deniedIpRanges
      .map(parseCidr)
      .filter((c): c is { base: number; mask: number } => c !== null);
  }

  /** The set of hosts explicitly allowed for navigation and replay. */
  private isExplicitlyAllowed(host: string): boolean {
    if (host === this.targetHost) return true;
    return this.spec.allowedDomains.some((d) => hostMatches(host, d, this.spec.allowSubdomains));
  }

  private isDeniedDomain(host: string): boolean {
    return this.spec.deniedDomains.some((d) => hostMatches(host, d, true));
  }

  private isDeniedIp(host: string): boolean {
    if (!isIpv4(host)) return false;
    const ip = ipv4ToInt(host);
    if (ip === null) return false;
    return this.deniedCidrs.some(({ base, mask }) => ((ip & mask) >>> 0) === base);
  }

  /**
   * Whether a host may be navigated to or replayed against. Explicitly-allowed
   * hosts (target + allow-list) bypass the private-range denial, since the
   * operator authorized them; everything else is default-deny.
   */
  hostInScope(host: string): ScopeDecision {
    const h = host.toLowerCase();
    if (this.isDeniedDomain(h)) return { allowed: false, reason: 'host is on the deny list' };
    if (this.isExplicitlyAllowed(h)) return { allowed: true, reason: 'explicitly allowed host' };
    if (this.isDeniedIp(h)) return { allowed: false, reason: 'host resolves to a denied IP range' };
    return { allowed: false, reason: 'host is outside the configured scope' };
  }

  urlInScope(url: string): ScopeDecision {
    let host: string;
    try {
      host = new URL(url).hostname;
    } catch {
      return { allowed: false, reason: 'unparseable URL' };
    }
    return this.hostInScope(host);
  }

  /** Whether a request should be excluded from authorization analysis (tracking/telemetry). */
  isExcludedFromAnalysis(url: string): boolean {
    let host: string;
    let path: string;
    try {
      const u = new URL(url);
      host = u.hostname.toLowerCase();
      path = u.pathname.toLowerCase();
    } catch {
      return true;
    }
    if (this.spec.excludeHosts.some((d) => hostMatches(host, d, true))) return true;
    if (this.spec.excludeUrlPatterns.some((p) => path.includes(p.toLowerCase()))) return true;
    return false;
  }

  /** Consume one unit of the request budget. Returns false when exhausted. */
  tryConsumeRequest(): boolean {
    if (this.requestCount >= this.spec.maxRequests) return false;
    this.requestCount += 1;
    return true;
  }

  remainingRequests(): number {
    return Math.max(0, this.spec.maxRequests - this.requestCount);
  }

  requestsUsed(): number {
    return this.requestCount;
  }

  /** Whether the wall-clock time budget is exhausted. */
  isTimeExhausted(): boolean {
    return this.elapsedSeconds() >= this.spec.maxDurationSeconds;
  }

  elapsedSeconds(): number {
    return (Date.now() - this.startedAt) / 1000;
  }

  /** Soft rate limiter: resolve after enough time has passed since the last call. */
  async throttle(): Promise<void> {
    const minGap = 1000 / this.spec.requestsPerSecond;
    const now = Date.now();
    const wait = this.lastRequestAt + minGap - now;
    this.lastRequestAt = Math.max(now, this.lastRequestAt + minGap);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }

  targetHostname(): string {
    return this.targetHost;
  }
}
