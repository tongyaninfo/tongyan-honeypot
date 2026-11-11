import { describe, expect, it } from 'vitest';
import { isServiceRunning, resolveServiceState } from './state';

describe('service runtime state', () => {
  it('uses the persisted current state when listener polling is empty', () => {
    expect(isServiceRunning('Running')).toBe(true);
    expect(resolveServiceState('Running')).toBe('Running');
  });

  it('prefers an active listener over a stale stopped state', () => {
    expect(isServiceRunning('Stopped', ['Running'])).toBe(true);
    expect(resolveServiceState('Stopped', ['Running'])).toBe('Running');
  });

  it('keeps failed state visible with the last startup error', () => {
    expect(isServiceRunning('Failed')).toBe(false);
    expect(resolveServiceState('Failed')).toBe('Failed');
  });
});
