import { describe, expect, it, vi } from 'vitest';
import access from './access';
import { toCurrentUser } from './services/identity';

vi.mock('@umijs/max', () => ({ request: vi.fn() }));

describe('access from the management identity contract', () => {
  it('recognizes the admin role returned by /auth/me', () => {
    const currentUser = toCurrentUser({ userId: 'sample-admin-id', username: 'sample-admin', roles: ['Administrator'] });
    expect(currentUser).toEqual({ userid: 'sample-admin-id', name: 'sample-admin', roles: ['Administrator'] });
    expect(access({ currentUser }).canAdmin).toBe(true);
  });

  it.each(['Administrator', 'administrator', 'ADMINISTRATOR', 'admin', 'Admin'])('recognizes the supported role %s without changing the identity', (role) => {
    const currentUser = toCurrentUser({ userId: 'sample-admin-id', username: 'sample-admin', roles: [role] });
    expect(access({ currentUser }).canAdmin).toBe(true);
    expect(currentUser.roles).toEqual([role]);
  });

  it('denies evidence controls to a real non-admin identity', () => {
    const currentUser = toCurrentUser({ userId: 'sample-reader-id', username: 'sample-reader', roles: ['Analyst'] });
    expect(access({ currentUser }).canAdmin).toBe(false);
  });

  it('does not let the legacy template field override actual roles', () => {
    expect(access({ currentUser: { roles: ['reader'], access: 'admin' } }).canAdmin).toBe(false);
  });

  it('does not infer privileges from an account name or a legacy access value', () => {
    expect(access({ currentUser: { name: 'admin', access: 'admin' } }).canAdmin).toBe(false);
  });

  it('handles an empty role list and a missing identity as non-admin', () => {
    expect(access({ currentUser: { roles: [] } }).canAdmin).toBe(false);
    expect(access({ currentUser: undefined }).canAdmin).toBe(false);
    expect(access(undefined).canAdmin).toBe(false);
  });
});
