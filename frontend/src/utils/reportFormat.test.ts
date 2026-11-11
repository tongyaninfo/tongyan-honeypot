import { expect, it } from 'vitest';
import { formatCoveragePercent, formatReportAxisTime, formatReportCount, formatUncoveredDuration, parseRecipients, reportDateRange } from './reportFormat';

it('uses Shanghai calendar days and an exclusive end for report ranges', () => {
  expect(reportDateRange('2026-11-10', '2026-11-10')).toEqual({ fromUtc: '2026-11-09T16:00:00.000Z', toUtc: '2026-11-10T16:00:00.000Z' });
  expect(reportDateRange('2026-11-11', '2026-11-10')).toBeUndefined();
});

it('preserves the distinction between zero and unavailable metrics', () => {
  expect(formatReportCount(0)).toBe('0');
  expect(formatReportCount(null)).toBe('暂不可用');
  expect(parseRecipients('one@example.test， two@example.test;one@example.test')).toEqual(['one@example.test', 'two@example.test']);
});

it('clips a report including today to now and rejects future calendar dates', () => {
  const now = new Date('2026-11-10T04:00:00Z');
  expect(reportDateRange('2026-11-09', '2026-11-10', now)).toEqual({ fromUtc: '2026-11-08T16:00:00.000Z', toUtc: now.toISOString() });
  expect(reportDateRange('2026-11-09', '2026-11-11', now)).toBeUndefined();
  expect(reportDateRange('2026-11-09', '2026-11-09', now)?.toUtc).toBe('2026-11-09T16:00:00.000Z');
});

it('does not round a short uncovered interval down to zero hours', () => {
  expect(formatUncoveredDuration(30)).toBe('少于 1 分钟');
  expect(formatUncoveredDuration(60)).toBe('1 分钟');
  expect(formatUncoveredDuration(61)).toBe('2 分钟');
  expect(formatUncoveredDuration(3599)).toBe('60 分钟');
  expect(formatUncoveredDuration(5400)).toBe('1.5 小时');
});

it('uses compact Shanghai axis labels and retains the year when a daily series crosses years', () => {
  expect(formatReportAxisTime('2026-11-09T16:00:00Z', 'hour')).toBe('00:00');
  expect(formatReportAxisTime('2026-11-10T04:00:00Z', 'hour')).toBe('12:00');
  expect(formatReportAxisTime('2026-11-09T16:00:00Z', 'day')).toBe('11-10');
  expect(formatReportAxisTime('2026-12-31T16:00:00Z', 'day', true)).toBe('2027-01-01');
});

it('does not round incomplete coverage to a misleading 100 percent', () => {
  expect(formatCoveragePercent(99.888, 'partial')).toBe('99.9%');
  expect(formatCoveragePercent(99.9, 'partial')).toBe('99.9%');
  expect(formatCoveragePercent(99.94, 'partial')).toBe('99.9%');
  expect(formatCoveragePercent(99.95, 'partial')).toBe('超过 99.9%');
  expect(formatCoveragePercent(99.97, 'partial')).toBe('超过 99.9%');
  expect(formatCoveragePercent(100, 'partial')).toBe('超过 99.9%');
  expect(formatCoveragePercent(99.8, 'partial')).toBe('99.8%');
  expect(formatCoveragePercent(100, 'complete')).toBe('100.0%');
});
