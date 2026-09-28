/**
 * Scan orchestrator.
 *
 * Wires the pipeline end to end:
 *   authorization gate → launch browser → per-user isolated crawl (observing
 *   the network) → two-pass URL normalization → per-user endpoint inventory →
 *   controlled cross-context replay + response comparison via the authz
 *   analyzers → report bundle.
 *
 * Sessions are kept open across the analysis phase because the replay engine
 * issues requests through each user's own isolated context.
 */
import type { Logger } from '../core/logger';
import type { Config } from '../config/schema';
import type {
  DiscoverySource,
  Finding,
  NavigationGraph,
  ObservedRequest,
  ScanResult,
} from '../core/types';
import { ScopeGuard } from '../core/scope';
import { RequestLog } from '../core/request-log';
import { BrowserEngine } from '../browser/engine';
import type { UserSession } from '../browser/session';
import { Explorer } from '../crawler/explorer';
import { NormalizerState } from '../analysis/normalize';
import { EndpointInventory } from '../analysis/inventory';
import { ReplayEngine } from '../analysis/replay';
import { AnalyzerRegistry, type AnalysisContext } from '../analysis/engine';
import { HorizontalAnalyzer } from '../analysis/horizontal';
import { VerticalAnalyzer } from '../analysis/vertical';
import { writeReports, type ReportBundle, type InventoryReportEntry } from '../report';

export class AuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

/** Resource types that are static assets and excluded from authz analysis. */
const ASSET_TYPES = new Set([
  'stylesheet',
  'image',
  'media',
  'font',
  'script',
  'texttrack',
  'manifest',
  'signedexchange',
  'ping',
  'cspviolationreport',
  'preflight',
  'favicon',
  'other',
]);

export interface ScanOptions {
  config: Config;
  logger: Logger;
  /** override the config output dir (CLI --output). */
  outputDir?: string;
  /** run the analysis phase (default true). */
  analyze?: boolean;
  /** write reports (default true). */
  report?: boolean;
  /** register additional analyzers (extensibility hook). */
  extraAnalyzers?: AnalyzerRegistry;
}

export interface ScanOutcome {
  scan: ScanResult;
  bundle: ReportBundle;
  reportPaths: string[];
  graphs: Map<string, NavigationGraph>;
  requestsById: Map<string, ObservedRequest>;
}

export async function runScan(opts: ScanOptions): Promise<ScanOutcome> {
  const { config, logger } = opts;
  const analyze = opts.analyze ?? true;
  const report = opts.report ?? true;

  if (!config.authorizedTesting) {
    throw new AuthorizationError(
      'Refusing to run: set `authorizedTesting: true` in the config to confirm you are ' +
        'authorized to test the target. This tool is for authorized assessments only.',
    );
  }

  const target = config.target.url;
  const startedAt = Date.now();
  const scope = new ScopeGuard(target, config.scope);
  const log = new RequestLog();
  const sink = (r: ObservedRequest) => log.add(r);

  const engine = new BrowserEngine({ browser: config.browser, proxy: config.proxy, logger });
  const sessions = new Map<string, UserSession>();
  const graphs = new Map<string, NavigationGraph>();
  let findings: Finding[] = [];
  const replayEngine = new ReplayEngine({
    spec: config.replay,
    scope,
    logger,
    requestContextFor: (user) => sessions.get(user)?.getContext().request,
  });

  try {
    await engine.launch();

    // 1. Per-user isolated crawl with network observation.
    for (const user of config.users) {
      logger.info({ user: user.name }, 'starting user crawl');
      try {
        const session = await engine.createSession(user, {
          targetUrl: target,
          navigationTimeoutMs: config.browser.navigationTimeoutMs,
          scope,
          sink,
          logger,
        });
        sessions.set(user.name, session);
        const explorer = new Explorer({ session, scope, crawl: config.crawl, logger, log, targetUrl: target });
        const result = await explorer.explore();
        graphs.set(user.name, result.graph.build());
        await session.flush();
      } catch (err) {
        logger.error({ user: user.name, err: (err as Error).message }, 'user crawl failed');
      }
    }

    // 2. Two-pass normalization over analyzable requests.
    const requestsById = log.idIndex();
    const analyzable = log.all().filter((r) => isAnalyzable(r, scope));
    const normalizer = new NormalizerState();
    for (const r of analyzable) normalizer.observe(r.method, r.url);
    for (const r of analyzable) r.normalized = normalizer.normalize(r.method, r.url);

    // 3. Per-user endpoint inventory.
    const inventory = new EndpointInventory();
    for (const u of config.users) inventory.ensureUser(u.name, u.role, u.privilegeLevel);
    for (const r of analyzable) inventory.add(r, discoverySourceOf(r));

    // 4. Analysis (controlled replay + comparison).
    if (analyze) {
      const registry = new AnalyzerRegistry().register(new HorizontalAnalyzer()).register(new VerticalAnalyzer());
      for (const extra of opts.extraAnalyzers?.list() ?? []) registry.register(extra);
      const ctx: AnalysisContext = {
        config,
        inventory,
        requestsById,
        graphs,
        users: config.users.map((u) => ({ name: u.name, role: u.role, privilegeLevel: u.privilegeLevel })),
        replayer: replayEngine,
        scope,
        logger,
        compareOptions: { ignoreFields: config.compare.ignoreFields, ignoreHeaders: config.compare.ignoreHeaders },
      };
      findings = await registry.run(ctx);
    }

    // 5. Assemble results.
    const finishedAt = Date.now();
    const outOfScopeBlocked = log.all().filter((r) => r.outOfScope).length;
    const scan: ScanResult = {
      target,
      startedAt,
      finishedAt,
      users: config.users.map((u) => u.name),
      stats: {
        nodes: sum([...graphs.values()].map((g) => g.nodes.length)),
        edges: sum([...graphs.values()].map((g) => g.edges.length)),
        requests: log.size(),
        endpoints: inventory.totalEndpoints(),
        replays: replayEngine.count(),
        outOfScopeBlocked,
      },
      findings,
      inventorySummary: inventory.summary(),
    };

    const inventoryReport: InventoryReportEntry[] = inventory.allUsers().map((inv) => ({
      user: inv.user,
      role: inv.role,
      privilegeLevel: inv.privilegeLevel,
      endpoints: [...inv.endpoints.values()].map((e) => ({
        signature: e.signature,
        method: e.method,
        pathTemplate: e.pathTemplate,
        sources: e.sources,
      })),
    }));

    const bundle: ReportBundle = {
      scan,
      graphs: [...graphs.values()],
      inventory: inventoryReport,
      configEcho: buildConfigEcho(config),
    };

    let reportPaths: string[] = [];
    if (report) {
      const output = opts.outputDir ? { ...config.output, dir: opts.outputDir } : config.output;
      reportPaths = writeReports(output, bundle, logger);
    }

    return { scan, bundle, reportPaths, graphs, requestsById };
  } finally {
    for (const s of sessions.values()) await s.close();
    await engine.close();
  }
}

function isAnalyzable(r: ObservedRequest, scope: ScopeGuard): boolean {
  if (r.outOfScope) return false;
  if (scope.isExcludedFromAnalysis(r.url)) return false;
  const rt = r.resourceType;
  if (rt && ASSET_TYPES.has(rt)) return false;
  return true;
}

function discoverySourceOf(r: ObservedRequest): DiscoverySource {
  switch (r.resourceType) {
    case 'websocket':
      return 'websocket';
    case 'eventsource':
      return 'eventsource';
    case 'xhr':
      return 'xhr';
    case 'fetch':
      return 'fetch';
    case 'document':
      return 'anchor';
    default:
      return 'network-resource';
  }
}

function buildConfigEcho(config: Config): Record<string, unknown> {
  return {
    target: config.target.url,
    authorizedTesting: config.authorizedTesting,
    users: config.users.map((u) => ({
      name: u.name,
      role: u.role,
      privilegeLevel: u.privilegeLevel,
      cookieCount: u.cookies.length,
      headerCount: u.headers.length,
    })),
    scope: {
      allowedDomains: config.scope.allowedDomains,
      allowSubdomains: config.scope.allowSubdomains,
      deniedDomains: config.scope.deniedDomains,
      maxRequests: config.scope.maxRequests,
      maxDurationSeconds: config.scope.maxDurationSeconds,
      requestsPerSecond: config.scope.requestsPerSecond,
    },
    crawl: config.crawl,
    replay: config.replay,
    proxy: config.proxy ? { type: config.proxy.type, server: maskProxy(config.proxy.url) } : null,
  };
}

function maskProxy(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return '[proxy]';
  }
}

function sum(nums: number[]): number {
  return nums.reduce((a, b) => a + b, 0);
}
