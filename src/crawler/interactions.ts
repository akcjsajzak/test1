/**
 * Interaction classification.
 *
 * The crawler discovers interactive elements and must decide, before touching
 * them, whether an interaction is safe to trigger automatically. The default
 * posture is conservative: only clearly-safe interactions (navigation, expand,
 * open, view, tab/menu toggles) are triggered unless the operator opts in to
 * more. Anything that reads as mutating requires confirmation; anything that
 * reads as destructive — including logout, which would end the session — is
 * never triggered by default.
 *
 * This module is pure so the classification rules can be unit-tested without a
 * browser.
 */
import type { SafetyClass } from '../core/types';

/** Words that indicate a destructive or session-ending action. */
export const DESTRUCTIVE_RE =
  /\b(delete|remove|destroy|disable|deactivate|deprovision|drop|reset|revoke|wipe|purge|erase|archive|unsubscribe|terminate|ban|block|log\s?out|sign\s?out|logout|signout)\b/i;

/** Words that indicate a state-mutating action (needs confirmation). */
export const MUTATING_RE =
  /\b(save|update|submit|create|add|new|send|pay|buy|order|checkout|apply|confirm|upload|invite|approve|reject|publish|transfer|withdraw|deposit|rename|move|merge|import|export|generate|issue|assign|enable)\b/i;

/** Descriptor of an interactive element extracted from the page. */
export interface InteractionDescriptor {
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

const SAFETY_RANK: Record<SafetyClass, number> = { safe: 0, confirm: 1, destructive: 2 };

/** Classify an interaction's safety. Highest-severity signal wins. */
export function classifyInteraction(d: InteractionDescriptor): SafetyClass {
  const haystack = [d.text, d.ariaLabel, d.name, d.title, d.href]
    .filter(Boolean)
    .join(' ')
    .trim();
  const method = (d.formMethod ?? '').toUpperCase();
  const type = (d.type ?? '').toLowerCase();

  let level: SafetyClass = 'safe';
  const bump = (s: SafetyClass) => {
    if (SAFETY_RANK[s] > SAFETY_RANK[level]) level = s;
  };

  if (method === 'DELETE') bump('destructive');
  if (method === 'POST' || method === 'PUT' || method === 'PATCH') bump('confirm');
  if (type === 'submit' || type === 'image') bump('confirm');

  if (haystack) {
    if (DESTRUCTIVE_RE.test(haystack)) bump('destructive');
    else if (MUTATING_RE.test(haystack)) bump('confirm');
  }
  return level;
}

/** Whether an interaction should be triggered given the destructive opt-in. */
export function shouldTrigger(safety: SafetyClass, includeDestructive: boolean): boolean {
  if (safety === 'safe') return true;
  if (safety === 'confirm') return includeDestructive;
  return false; // destructive: never auto-trigger, even with the opt-in.
}

/** Roles considered interactive for discovery purposes. */
export const INTERACTIVE_ROLES = new Set([
  'button',
  'tab',
  'menuitem',
  'menuitemcheckbox',
  'menuitemradio',
  'link',
  'treeitem',
  'option',
  'switch',
]);
