/**
 * Navigation / discovery graph.
 *
 * Nodes are distinct browser states (a URL/route reached under a user context);
 * edges are the actions or events that moved between them (a click, a pushState,
 * a redirect) and carry the network requests they produced. The graph exists to
 * *explain* how a resource was discovered — every finding can be traced back to
 * the action that first surfaced the endpoint.
 */
import { randomUUID } from 'node:crypto';
import type {
  DiscoverySource,
  GraphEdge,
  GraphNode,
  NavigationGraph,
  SafetyClass,
} from '../core/types';

export class GraphBuilder {
  private readonly user: string;
  private readonly nodes = new Map<string, GraphNode>();
  private readonly edges = new Map<string, GraphEdge>();
  /** dedup key (user + url + state) -> node id. */
  private readonly nodeKeys = new Map<string, string>();

  constructor(user: string) {
    this.user = user;
  }

  private keyFor(url: string, state?: string): string {
    return `${url}::${state ?? ''}`;
  }

  /** Get an existing node for this URL/state or create one. */
  getOrCreateNode(url: string, opts: { route?: string; title?: string; state?: string } = {}): GraphNode {
    const key = this.keyFor(url, opts.state);
    const existing = this.nodeKeys.get(key);
    if (existing) return this.nodes.get(existing)!;
    const node: GraphNode = {
      id: `n_${randomUUID().slice(0, 8)}`,
      user: this.user,
      url,
      route: opts.route,
      title: opts.title,
      timestamp: Date.now(),
      state: opts.state,
      incomingEdges: [],
      outgoingEdges: [],
    };
    this.nodes.set(node.id, node);
    this.nodeKeys.set(key, node.id);
    return node;
  }

  hasNode(url: string, state?: string): boolean {
    return this.nodeKeys.has(this.keyFor(url, state));
  }

  /** Record an action/event edge between two nodes (to may be undefined). */
  addEdge(params: {
    from: string;
    to?: string;
    source: DiscoverySource;
    label: string;
    safety?: SafetyClass;
    requestIds?: string[];
  }): GraphEdge {
    const edge: GraphEdge = {
      id: `e_${randomUUID().slice(0, 8)}`,
      from: params.from,
      to: params.to,
      source: params.source,
      label: params.label,
      safety: params.safety ?? 'safe',
      timestamp: Date.now(),
      requestIds: params.requestIds ?? [],
    };
    this.edges.set(edge.id, edge);
    this.nodes.get(params.from)?.outgoingEdges.push(edge.id);
    if (params.to) this.nodes.get(params.to)?.incomingEdges.push(edge.id);
    return edge;
  }

  /** Attach a request id to an edge after the fact (once observed). */
  attachRequestToEdge(edgeId: string, requestId: string): void {
    const edge = this.edges.get(edgeId);
    if (edge && !edge.requestIds.includes(requestId)) edge.requestIds.push(requestId);
  }

  nodeCount(): number {
    return this.nodes.size;
  }

  edgeCount(): number {
    return this.edges.size;
  }

  /** Find the edge whose requests include the given request id (for provenance). */
  findEdgeForRequest(requestId: string): GraphEdge | undefined {
    for (const edge of this.edges.values()) {
      if (edge.requestIds.includes(requestId)) return edge;
    }
    return undefined;
  }

  build(): NavigationGraph {
    return {
      user: this.user,
      nodes: [...this.nodes.values()],
      edges: [...this.edges.values()],
    };
  }
}
