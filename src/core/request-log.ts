/**
 * Shared, append-only log of observed requests.
 *
 * The network collectors (one per user) push into this log via their sink; the
 * crawler reads "requests since a mark" to attribute them to the graph edge
 * that produced them, and the analysis phase reads the whole log and the
 * by-id index. Keeping this in one small class decouples the collector, the
 * crawler and the orchestrator.
 */
import type { ObservedRequest } from './types';

export class RequestLog {
  private readonly items: ObservedRequest[] = [];
  private readonly index = new Map<string, ObservedRequest>();

  add(req: ObservedRequest): void {
    this.items.push(req);
    this.index.set(req.id, req);
  }

  /** Current number of logged requests; use as a mark before an action. */
  size(): number {
    return this.items.length;
  }

  /** Requests logged since a previous mark. */
  since(mark: number): ObservedRequest[] {
    return this.items.slice(mark);
  }

  all(): ObservedRequest[] {
    return [...this.items];
  }

  byId(id: string): ObservedRequest | undefined {
    return this.index.get(id);
  }

  idIndex(): Map<string, ObservedRequest> {
    return new Map(this.index);
  }
}
