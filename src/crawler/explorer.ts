/**
 * SPA-aware crawler / explorer.
 *
 * Drives one user's isolated session to explore the application within strict
 * budgets, combining several discovery sources (anchors, DOM URL attributes,
 * form actions, history pushState/replaceState, and — via the network collector
 * — fetch/XHR/WebSocket traffic). It triggers only safe interactions by default
 * and records every step in the navigation graph so discoveries are explainable.
 *
 * Design bias (per the spec priorities): reproducible, low-load exploration over
 * maximal request volume. Navigation is the deterministic backbone; interactions
 * are bounded and conservative.
 */
import type { Logger } from '../core/logger';
import type { ScopeGuard } from '../core/scope';
import type { CrawlSpec } from '../config/schema';
import type { RequestLog } from '../core/request-log';
import type { UserSession } from '../browser/session';
import { GraphBuilder } from '../graph/model';
import { normalizeRequest } from '../analysis/normalize';
import { extractLinks, tagInteractives } from './discovery';
import { classifyInteraction, shouldTrigger } from './interactions';

const ASSET_RE = /\.(js|mjs|css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|json|xml|pdf|zip|mp4|webm)(\?|$)/i;
const PER_TEMPLATE_CAP = 3;

interface FrontierItem {
  url: string;
  depth: number;
  fromNodeId?: string;
  via: 'seed' | 'anchor' | 'dom-url' | 'history-pushstate' | 'interaction';
}

export interface ExploreResult {
  graph: GraphBuilder;
  pagesVisited: number;
  actionsPerformed: number;
}

export class Explorer {
  private readonly session: UserSession;
  private readonly scope: ScopeGuard;
  private readonly crawl: CrawlSpec;
  private readonly logger: Logger;
  private readonly log: RequestLog;
  private readonly targetUrl: string;
  private readonly graph: GraphBuilder;

  private readonly visited = new Set<string>();
  private readonly templateCounts = new Map<string, number>();
  private pagesVisited = 0;
  private actionsPerformed = 0;
  private readonly startedAt = Date.now();

  constructor(params: {
    session: UserSession;
    scope: ScopeGuard;
    crawl: CrawlSpec;
    logger: Logger;
    log: RequestLog;
    targetUrl: string;
  }) {
    this.session = params.session;
    this.scope = params.scope;
    this.crawl = params.crawl;
    this.logger = params.logger;
    this.log = params.log;
    this.targetUrl = params.targetUrl;
    this.graph = new GraphBuilder(params.session.name);
  }

  private budgetExhausted(): boolean {
    const elapsed = (Date.now() - this.startedAt) / 1000;
    return (
      this.pagesVisited >= this.crawl.maxPages ||
      this.actionsPerformed >= this.crawl.maxActions ||
      elapsed >= this.crawl.maxDurationSeconds ||
      this.log.size() >= this.crawl.maxRequests ||
      this.scope.isTimeExhausted() ||
      this.scope.remainingRequests() <= 0
    );
  }

  /** Route dedup/visit key: the normalized path template (bounds SPA id fan-out). */
  private templateKey(url: string): string {
    try {
      const n = normalizeRequest('GET', url);
      return `${n.host}${n.pathTemplate}`;
    } catch {
      return url;
    }
  }

  private canVisit(url: string): boolean {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      return false;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    if (new URL(this.targetUrl).origin !== u.origin) return false; // never leave the origin
    if (!this.scope.urlInScope(url).allowed) return false;
    if (u.pathname.startsWith('/api/')) return false; // APIs are observed, not navigated
    if (ASSET_RE.test(u.pathname)) return false;
    return true;
  }

  private enqueueDiscoveries(
    links: { anchors: string[]; dataRoutes: string[]; formActions: Array<{ action: string; method: string }>; pushStateRoutes: string[] },
    fromNodeId: string,
    depth: number,
    frontier: FrontierItem[],
  ): void {
    if (depth >= this.crawl.maxDepth) return;
    const add = (url: string, via: FrontierItem['via']) => {
      if (this.canVisit(url)) frontier.push({ url, depth: depth + 1, fromNodeId, via });
    };
    links.anchors.forEach((u) => add(u, 'anchor'));
    links.dataRoutes.forEach((u) => add(u, 'dom-url'));
    links.pushStateRoutes.forEach((u) => add(u, 'history-pushstate'));
    // Form GET actions are navigations; POST/others are left to the replay policy.
    links.formActions.filter((f) => f.method === 'GET').forEach((f) => add(f.action, 'dom-url'));
  }

  async explore(): Promise<ExploreResult> {
    const seedNode = this.graph.getOrCreateNode(this.targetUrl, { route: safePath(this.targetUrl) });
    const frontier: FrontierItem[] = [{ url: this.targetUrl, depth: 0, via: 'seed', fromNodeId: seedNode.id }];

    while (frontier.length > 0 && !this.budgetExhausted()) {
      const item = frontier.shift()!;
      const tkey = this.templateKey(item.url);
      const tcount = this.templateCounts.get(tkey) ?? 0;
      const concreteKey = new URL(item.url).pathname + new URL(item.url).search;
      if (this.visited.has(concreteKey)) continue;
      if (tcount >= PER_TEMPLATE_CAP) continue;
      this.visited.add(concreteKey);
      this.templateCounts.set(tkey, tcount + 1);

      await this.scope.throttle();
      const mark = this.log.size();
      await this.session.goto(item.url);
      await this.settle();
      this.pagesVisited += 1;

      const landedUrl = this.session.currentRoute() ?? item.url;
      const node = this.graph.getOrCreateNode(landedUrl, {
        route: safePath(landedUrl),
        title: await this.safeTitle(),
      });
      const navReqs = this.log.since(mark).map((r) => r.id);
      this.graph.addEdge({
        from: item.fromNodeId ?? seedNode.id,
        to: node.id,
        source: item.via === 'seed' ? 'seed' : item.via === 'history-pushstate' ? 'history-pushstate' : 'anchor',
        label: `navigate ${safePath(landedUrl)}`,
        requestIds: navReqs,
      });

      const links = await this.safeExtractLinks();
      this.enqueueDiscoveries(links, node.id, item.depth, frontier);

      if (this.crawl.interact) {
        await this.runInteractions(node.id, item.depth, frontier);
      }
    }

    this.logger.info(
      { user: this.session.name, pages: this.pagesVisited, actions: this.actionsPerformed, requests: this.log.size() },
      'exploration finished',
    );
    return { graph: this.graph, pagesVisited: this.pagesVisited, actionsPerformed: this.actionsPerformed };
  }

  private async runInteractions(nodeId: string, depth: number, frontier: FrontierItem[]): Promise<void> {
    let interactives;
    try {
      interactives = await tagInteractives(this.session.getPage());
    } catch {
      return;
    }
    const routeBefore = this.session.currentRoute();
    for (const desc of interactives) {
      if (this.budgetExhausted()) break;
      const safety = classifyInteraction(desc);
      if (!shouldTrigger(safety, this.crawl.includeDestructive)) {
        // Record the discovered-but-not-triggered capability for explainability.
        this.graph.addEdge({
          from: nodeId,
          source: 'interaction',
          label: `skip ${safety} interaction: ${desc.text ?? desc.tag}`,
          safety,
        });
        continue;
      }
      await this.scope.throttle();
      const mark = this.log.size();
      const clicked = await this.safeClick(desc.aaId);
      if (!clicked) continue;
      await this.settle();
      this.actionsPerformed += 1;

      const routeAfter = this.session.currentRoute();
      const reqIds = this.log.since(mark).map((r) => r.id);
      const changed = routeAfter && routeAfter !== routeBefore;
      const targetNode = changed
        ? this.graph.getOrCreateNode(routeAfter!, { route: safePath(routeAfter!) })
        : undefined;
      this.graph.addEdge({
        from: nodeId,
        to: targetNode?.id,
        source: 'interaction',
        label: `${desc.role ?? desc.tag} "${(desc.text ?? '').slice(0, 40)}"`,
        safety,
        requestIds: reqIds,
      });

      if (changed) {
        // The interaction navigated (SPA route change). Enqueue the new route and
        // stop interacting with this now-stale DOM; the new route is explored later.
        const links = await this.safeExtractLinks();
        this.enqueueDiscoveries(links, targetNode!.id, depth, frontier);
        if (this.canVisit(routeAfter!)) {
          frontier.push({ url: routeAfter!, depth: depth + 1, fromNodeId: targetNode!.id, via: 'interaction' });
        }
        break;
      }
    }
  }

  private async settle(): Promise<void> {
    const page = this.session.getPage();
    try {
      await page.waitForLoadState('networkidle', { timeout: Math.max(1000, this.crawl.settleMs * 3) });
    } catch {
      /* networkidle may not be reached for long-polling apps; fall through */
    }
    if (this.crawl.settleMs > 0) await page.waitForTimeout(this.crawl.settleMs);
  }

  private async safeExtractLinks() {
    try {
      return await extractLinks(this.session.getPage());
    } catch {
      return { anchors: [], dataRoutes: [], formActions: [], pushStateRoutes: [] };
    }
  }

  private async safeClick(aaId: number): Promise<boolean> {
    try {
      await this.session.getPage().click(`[data-aa-id="${aaId}"]`, { timeout: 2000, noWaitAfter: true });
      return true;
    } catch {
      return false;
    }
  }

  private async safeTitle(): Promise<string | undefined> {
    try {
      return (await this.session.getPage().title()) || undefined;
    } catch {
      return undefined;
    }
  }
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
