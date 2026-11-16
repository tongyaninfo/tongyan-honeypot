import { cleanup, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import type { ThreatIpProfile } from '@/services/honeypot/api';
import { RiskSourcesCard } from './OverviewActivityTables';

vi.mock('@umijs/max', () => ({
  Link: ({ to, children }: { to: string; children: ReactNode }) => (
    <a href={to}>{children}</a>
  ),
}));
vi.mock('@/components/SourceIp', () => ({
  default: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

afterEach(cleanup);

function threat(ip: number, score: number, attempts: number, minute: number): ThreatIpProfile {
  return {
    threatId: `threat-${ip}`,
    sourceIp: `192.0.2.${ip}`,
    firstSeenUtc: '2026-11-15T00:00:00Z',
    lastSeenUtc: new Date(Date.UTC(2026, 10, 15, 1, minute)).toISOString(),
    currentScore: score,
    maxScore: score,
    scoreVersion: 'v1',
    status: 'Observed',
    attemptCount: attempts,
    sessionCount: 1,
    activeSessionCount: 0,
    authenticationAttemptCount: attempts,
    protocolViolationCount: 0,
    servicesTouched: ['ssh'],
    portsTouched: [22],
  };
}

it('显示风险分最高的八个来源，同分时按认证尝试次数和最近出现时间排序', () => {
  render(<RiskSourcesCard loading={false} threats={[
    threat(1, 10, 100, 59),
    threat(2, 65, 4, 3),
    threat(3, 55, 99, 59),
    threat(4, 65, 4, 9),
    threat(5, 65, 9, 5),
    threat(6, 45, 0, 59),
    threat(7, 35, 0, 59),
    threat(8, 25, 0, 59),
    threat(9, 75, 1, 1),
    threat(10, 5, 100, 59),
  ]} />);

  const sources = within(screen.getByRole('table')).getAllByRole('link');
  expect(sources.map((source) => source.textContent)).toEqual(
    [9, 5, 4, 2, 3, 6, 7, 8].map((ip) => `192.0.2.${ip}`),
  );
});
