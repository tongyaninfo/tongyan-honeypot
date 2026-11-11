import { describe, expect, it } from 'vitest';
import defaultSettings from '../config/defaultSettings';
import routes from '../config/routes';

describe('Honeypot frontend baseline', () => {
  it('uses the Honeypot brand settings', () => {
    expect(defaultSettings.title).toBe('通研 Honeypot');
    expect(defaultSettings.logo).toBe('/assets/brand/tyinfo-logo-horizontal.png');
  });

  it('exposes reports and keeps system notification management administrator-only', () => {
    const paths = routes.map((route) => route.path);

    expect(paths).toEqual(['/user', '/setup', '/overview', '/services', '/reports', '/sensors', '/events', '/threats', '/credentials', '/system', '/', '/*']);
    expect(routes.find((route) => route.path === '/reports')?.access).toBeUndefined();
    const system = routes.find((route) => route.path === '/system');
    expect(system?.access).toBe('canAdmin');
    expect(system?.routes?.find((route) => route.path === '/system/ip-location')).toMatchObject({ access: 'canAdmin' });
    expect(system?.routes?.find((route) => route.path === '/system/notifications')).toMatchObject({ access: 'canAdmin' });
    expect(system?.routes?.find((route) => route.path === '/system/mail-records')).toMatchObject({ access: 'canAdmin' });
  });
});
