/**
 * DOM/route discovery helpers that run inside the page.
 *
 * These combine several discovery sources the spec requires: <a href>, DOM URL
 * attributes (data-route/data-href/data-url), form actions, and client-side
 * route changes recorded from the history hook. The network collector supplies
 * the remaining sources (fetch/XHR/WebSocket/EventSource) out of band.
 */
import type { Page } from 'playwright-core';

export interface LinkDiscovery {
  anchors: string[];
  dataRoutes: string[];
  formActions: Array<{ action: string; method: string }>;
  pushStateRoutes: string[];
}

export interface RawInteractive {
  aaId: number;
  tag: string;
  role?: string;
  type?: string;
  text?: string;
  ariaLabel?: string;
  name?: string;
  title?: string;
  href?: string;
  formMethod?: string;
}

/** Extract link-like URLs and recorded SPA routes from the page. */
export async function extractLinks(page: Page): Promise<LinkDiscovery> {
  return page.evaluate(() => {
    const abs = (u: string | null | undefined): string | null => {
      if (!u) return null;
      try {
        return new URL(u, location.href).href;
      } catch {
        return null;
      }
    };
    const anchors: string[] = [];
    document.querySelectorAll('a[href], area[href]').forEach((a) => {
      const h = abs(a.getAttribute('href'));
      if (h && !h.startsWith('javascript:')) anchors.push(h);
    });
    const dataRoutes: string[] = [];
    document.querySelectorAll('[data-route], [data-href], [data-url]').forEach((e) => {
      const v =
        e.getAttribute('data-route') || e.getAttribute('data-href') || e.getAttribute('data-url');
      const h = abs(v);
      if (h) dataRoutes.push(h);
    });
    const formActions: Array<{ action: string; method: string }> = [];
    document.querySelectorAll('form').forEach((f) => {
      const action = abs(f.getAttribute('action') || location.href);
      if (action) formActions.push({ action, method: (f.getAttribute('method') || 'GET').toUpperCase() });
    });
    const w = window as unknown as { __aa_routes?: string[] };
    const pushStateRoutes = Array.isArray(w.__aa_routes) ? [...w.__aa_routes] : [];
    return { anchors, dataRoutes, formActions, pushStateRoutes };
  });
}

/**
 * Tag interactive elements with a stable data-aa-id and return their
 * descriptors, so the crawler can click them by selector. Re-run after each
 * render because SPA updates invalidate previous tags.
 */
export async function tagInteractives(page: Page, limit = 120): Promise<RawInteractive[]> {
  return page.evaluate((max: number) => {
    const selector = [
      'button',
      'input[type=submit]',
      'input[type=button]',
      'input[type=image]',
      'summary',
      '[role=button]',
      '[role=tab]',
      '[role=menuitem]',
      '[role=menuitemcheckbox]',
      '[role=menuitemradio]',
      '[role=switch]',
      '[role=treeitem]',
      '[onclick]',
      '[data-action]',
    ].join(',');
    const out: RawInteractive[] = [];
    const seen = new Set<Element>();
    let id = 0;
    const nodes = Array.from(document.querySelectorAll(selector));
    for (const e of nodes) {
      if (seen.has(e) || id >= max) continue;
      seen.add(e);
      const he = e as HTMLElement;
      // Skip hidden/disabled elements.
      const style = window.getComputedStyle(he);
      if (style.display === 'none' || style.visibility === 'hidden') continue;
      if ((he as HTMLButtonElement).disabled) continue;
      const aaId = id++;
      he.setAttribute('data-aa-id', String(aaId));
      const form = (he as HTMLInputElement).form;
      out.push({
        aaId,
        tag: he.tagName.toLowerCase(),
        role: he.getAttribute('role') || undefined,
        type: he.getAttribute('type') || undefined,
        text: (he.textContent || '').trim().slice(0, 80) || undefined,
        ariaLabel: he.getAttribute('aria-label') || undefined,
        name: he.getAttribute('name') || undefined,
        title: he.getAttribute('title') || undefined,
        href: he.getAttribute('href') || undefined,
        formMethod: form ? (form.getAttribute('method') || 'GET').toUpperCase() : undefined,
      });
    }
    return out;
  }, limit);
}
