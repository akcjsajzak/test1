import { describe, it, expect } from 'vitest';
import { classifyInteraction, shouldTrigger } from '../../src/crawler/interactions';

describe('classifyInteraction', () => {
  it('treats navigation/expand as safe', () => {
    expect(classifyInteraction({ tag: 'button', text: 'View details' })).toBe('safe');
    expect(classifyInteraction({ tag: 'button', role: 'tab', text: 'Overview' })).toBe('safe');
  });
  it('treats save/submit/create as confirm', () => {
    expect(classifyInteraction({ tag: 'button', text: 'Save changes' })).toBe('confirm');
    expect(classifyInteraction({ tag: 'input', type: 'submit', text: 'Submit' })).toBe('confirm');
    expect(classifyInteraction({ tag: 'button', text: 'Create user', formMethod: 'POST' })).toBe('confirm');
  });
  it('treats delete/remove as destructive', () => {
    expect(classifyInteraction({ tag: 'button', text: 'Delete account' })).toBe('destructive');
    expect(classifyInteraction({ tag: 'a', text: 'Remove', formMethod: 'DELETE' })).toBe('destructive');
  });
  it('treats logout/sign out as destructive (session-ending)', () => {
    expect(classifyInteraction({ tag: 'a', text: 'Log out' })).toBe('destructive');
    expect(classifyInteraction({ tag: 'button', text: 'Sign out' })).toBe('destructive');
  });
});

describe('shouldTrigger', () => {
  it('always triggers safe interactions', () => {
    expect(shouldTrigger('safe', false)).toBe(true);
  });
  it('triggers confirm only with opt-in', () => {
    expect(shouldTrigger('confirm', false)).toBe(false);
    expect(shouldTrigger('confirm', true)).toBe(true);
  });
  it('never triggers destructive, even with opt-in', () => {
    expect(shouldTrigger('destructive', true)).toBe(false);
  });
});
