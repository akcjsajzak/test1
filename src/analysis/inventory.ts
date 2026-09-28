/**
 * Per-user endpoint inventory.
 *
 * Groups observed requests by normalized signature within each user context.
 * The inventory is the basis for cross-user comparison: the horizontal analyzer
 * asks "did user B ever reach the signature that user A reached?" and the
 * vertical analyzer asks "can a lower-privilege user reach a signature only a
 * higher-privilege user reached?".
 */
import type {
  DiscoverySource,
  EndpointObservation,
  ObservedRequest,
  UserInventory,
} from '../core/types';

function isSuccess(status?: number): boolean {
  return status !== undefined && status >= 200 && status < 300;
}

export class EndpointInventory {
  private readonly users = new Map<string, UserInventory>();
  /** representativeId -> whether it was a 2xx, to prefer successes. */
  private readonly representativeIsSuccess = new Map<string, boolean>();

  /** Register a user context up front so empty inventories still appear. */
  ensureUser(user: string, role?: string, privilegeLevel?: number): UserInventory {
    let inv = this.users.get(user);
    if (!inv) {
      inv = { user, role, privilegeLevel, endpoints: new Map() };
      this.users.set(user, inv);
    } else {
      if (role !== undefined) inv.role = role;
      if (privilegeLevel !== undefined) inv.privilegeLevel = privilegeLevel;
    }
    return inv;
  }

  /** Add one normalized request to its user's inventory. */
  add(req: ObservedRequest, source: DiscoverySource = 'network-resource'): void {
    if (!req.normalized) return;
    const inv = this.ensureUser(req.user);
    const sig = req.normalized.signature;
    let obs = inv.endpoints.get(sig);
    if (!obs) {
      obs = {
        signature: sig,
        method: req.normalized.method,
        pathTemplate: req.normalized.pathTemplate,
        host: req.normalized.host,
        requestIds: [],
        representativeId: req.id,
        sources: [],
        firstSeen: req.timing.startedAt,
      };
      inv.endpoints.set(sig, obs);
      this.representativeIsSuccess.set(`${inv.user}:${sig}`, isSuccess(req.status));
    }
    obs.requestIds.push(req.id);
    if (!obs.sources.includes(source)) obs.sources.push(source);

    // Prefer a 2xx observation as representative over a non-success one.
    const repKey = `${inv.user}:${sig}`;
    const repSuccess = this.representativeIsSuccess.get(repKey) ?? false;
    if (isSuccess(req.status) && !repSuccess) {
      obs.representativeId = req.id;
      this.representativeIsSuccess.set(repKey, true);
    }
    obs.firstSeen = Math.min(obs.firstSeen, req.timing.startedAt);
  }

  getUser(user: string): UserInventory | undefined {
    return this.users.get(user);
  }

  allUsers(): UserInventory[] {
    return [...this.users.values()];
  }

  userNames(): string[] {
    return [...this.users.keys()];
  }

  /** All distinct signatures across all users, with the set of users that hit each. */
  signatureIndex(): Map<string, Set<string>> {
    const index = new Map<string, Set<string>>();
    for (const inv of this.users.values()) {
      for (const sig of inv.endpoints.keys()) {
        let set = index.get(sig);
        if (!set) {
          set = new Set();
          index.set(sig, set);
        }
        set.add(inv.user);
      }
    }
    return index;
  }

  /** Look up an endpoint observation for a specific user + signature. */
  lookup(user: string, signature: string): EndpointObservation | undefined {
    return this.users.get(user)?.endpoints.get(signature);
  }

  totalEndpoints(): number {
    let n = 0;
    for (const inv of this.users.values()) n += inv.endpoints.size;
    return n;
  }

  summary(): Array<{ user: string; role?: string; endpoints: number }> {
    return this.allUsers().map((u) => ({ user: u.user, role: u.role, endpoints: u.endpoints.size }));
  }
}
