import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiResult, IPLocationBatch, IPLocationResult } from './api';
import { IPLocationClient } from './ipLocationClient';

vi.mock('@umijs/max', () => ({ request: vi.fn() }));
const response = (items: IPLocationResult[]): ApiResult<IPLocationBatch> => ({
  success: true, code: 'OK', message: '', data: { enabled: true, items },
});

describe('shared IP location scheduler', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

  it('deduplicates cells and follows pending results without delaying the IP', async () => {
    const resolve = vi.fn().mockResolvedValueOnce(response([{ ip: '1.1.1.1', status: 'pending' }]))
      .mockResolvedValueOnce(response([{ ip: '1.1.1.1', status: 'resolved', country: '示例国家' }]));
    const client = new IPLocationClient(resolve);
    const first = client.subscribe('1.1.1.1', vi.fn());
    const second = client.subscribe('1.1.1.1', vi.fn());
    expect(client.getSnapshot('1.1.1.1')).toBeUndefined();
    await vi.advanceTimersByTimeAsync(30);
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve.mock.calls[0][0]).toEqual(['1.1.1.1']);
    expect(client.getSnapshot('1.1.1.1')?.status).toBe('pending');
    await vi.advanceTimersByTimeAsync(1000);
    expect(client.getSnapshot('1.1.1.1')?.country).toBe('示例国家');
    first(); second();
    await vi.advanceTimersByTimeAsync(120000);
    expect(resolve).toHaveBeenCalledTimes(2);
  });

  it('bounds each batch and never runs concurrent batch requests', async () => {
    let complete: ((value: ApiResult<IPLocationBatch>) => void) | undefined;
    const resolve = vi.fn().mockImplementation(() => new Promise((done) => { complete = done; }));
    const client = new IPLocationClient(resolve);
    const unsubscribers = Array.from({ length: 120 }, (_, index) => client.subscribe(`192.0.2.${index + 1}`, vi.fn()));
    await vi.advanceTimersByTimeAsync(30);
    expect(resolve.mock.calls[0][0]).toHaveLength(100);
    await vi.advanceTimersByTimeAsync(10000);
    expect(resolve).toHaveBeenCalledTimes(1);
    complete?.(response(resolve.mock.calls[0][0].map((ip: string) => ({ ip, status: 'reserved' }))));
    await vi.advanceTimersByTimeAsync(30);
    expect(resolve).toHaveBeenCalledTimes(2);
    expect(resolve.mock.calls[1][0]).toHaveLength(20);
    unsubscribers.forEach((unsubscribe) => unsubscribe());
    expect(resolve.mock.calls[1][1].aborted).toBe(true);
  });

  it('invalidates cached locations and discards a response from the old configuration', async () => {
    let oldComplete: ((value: ApiResult<IPLocationBatch>) => void) | undefined;
    const resolve = vi.fn().mockImplementationOnce(() => new Promise((done) => { oldComplete = done; }))
      .mockResolvedValue(response([{ ip: '1.1.1.1', status: 'disabled' }]));
    const client = new IPLocationClient(resolve);
    const unsubscribe = client.subscribe('1.1.1.1', vi.fn());
    await vi.advanceTimersByTimeAsync(30);
    client.invalidate();
    expect(resolve.mock.calls[0][1].aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(30);
    oldComplete?.(response([{ ip: '1.1.1.1', status: 'resolved', country: '旧位置' }]));
    await vi.advanceTimersByTimeAsync(1);
    expect(client.getSnapshot('1.1.1.1')?.status).toBe('disabled');
    unsubscribe();
  });

  it('backs off failures and releases the request on final unmount', async () => {
    const resolve = vi.fn().mockRejectedValue(new Error('Network unavailable'));
    const client = new IPLocationClient(resolve);
    const unsubscribe = client.subscribe('1.1.1.1', vi.fn());
    await vi.advanceTimersByTimeAsync(30);
    expect(client.getSnapshot('1.1.1.1')?.status).toBe('failed');
    await vi.advanceTimersByTimeAsync(14000);
    expect(resolve).toHaveBeenCalledTimes(1);
    unsubscribe();
    await vi.advanceTimersByTimeAsync(120000);
    expect(resolve).toHaveBeenCalledTimes(1);
  });
});
