/**
 * Analyzer engine and registry.
 *
 * This is the extensibility seam: a detection engine implements {@link Analyzer}
 * and is registered with {@link AnalyzerRegistry}. Each analyzer receives an
 * {@link AnalysisContext} exposing the endpoint inventory, the raw observed
 * requests, the navigation graphs and a controlled {@link Replayer}. Adding a
 * new detector (e.g. IDOR heuristics, JWT confusion, method-override) is a
 * matter of writing one file and calling `registry.register(...)`.
 */
import type { CompareOptions } from './compare';
import type { EndpointInventory } from './inventory';
import type { Logger } from '../core/logger';
import type { ScopeGuard } from '../core/scope';
import type { Config } from '../config/schema';
import type { Finding, NavigationGraph, ObservedRequest, ReplayResult } from '../core/types';

/** A controlled request replayer, implemented by the replay engine. */
export interface Replayer {
  /**
   * Replay a previously observed request under a different user context.
   * Implementations enforce the replay policy (safe methods only by default,
   * secret filtering, scope) and may return `{ requested: false }` when skipped.
   */
  replay(request: ObservedRequest, asUser: string): Promise<ReplayResult>;
}

export interface UserInfo {
  name: string;
  role?: string;
  privilegeLevel?: number;
  /** optional tenant/org identifier for cross-tenant reasoning. */
  tenant?: string;
  /** whether this context carries authentication material (cookies/headers/login). */
  authenticated?: boolean;
}

/** Everything an analyzer needs, without depending on concrete engine classes. */
export interface AnalysisContext {
  config: Config;
  inventory: EndpointInventory;
  requestsById: Map<string, ObservedRequest>;
  graphs: Map<string, NavigationGraph>;
  users: UserInfo[];
  replayer: Replayer;
  scope: ScopeGuard;
  logger: Logger;
  compareOptions: CompareOptions;
}

/** A detection engine. */
export interface Analyzer {
  /** short stable id, used as a finding type prefix (e.g. AUTHZ-HORIZONTAL). */
  id: string;
  /** human-readable title for logs/reports. */
  title: string;
  analyze(ctx: AnalysisContext): Promise<Finding[]>;
}

export class AnalyzerRegistry {
  private readonly analyzers: Analyzer[] = [];

  register(analyzer: Analyzer): this {
    this.analyzers.push(analyzer);
    return this;
  }

  list(): Analyzer[] {
    return [...this.analyzers];
  }

  /** Run every registered analyzer and return the concatenated findings. */
  async run(ctx: AnalysisContext): Promise<Finding[]> {
    const all: Finding[] = [];
    for (const analyzer of this.analyzers) {
      const started = Date.now();
      try {
        const findings = await analyzer.analyze(ctx);
        ctx.logger.info(
          { analyzer: analyzer.id, findings: findings.length, ms: Date.now() - started },
          `analyzer ${analyzer.id} finished`,
        );
        all.push(...findings);
      } catch (err) {
        ctx.logger.error(
          { analyzer: analyzer.id, err: (err as Error).message },
          `analyzer ${analyzer.id} failed`,
        );
      }
    }
    return all;
  }
}
