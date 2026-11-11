import { type IPLocationResult, maxIPLocationInputLength, resolveIPLocations } from './api';

interface Entry {
  result?: IPLocationResult;
  nextAt: number;
  listeners: Set<() => void>;
}

const cacheLimit = 1000;
const batchLimit = 100;

/** 页面共享一个调度器：合并可见 IP，单请求轮询，离开页面即停止。 */
export class IPLocationClient {
  private entries = new Map<string, Entry>();
  private timer?: ReturnType<typeof setTimeout>;
  private request?: AbortController;
  private generation = 0;

  constructor(private resolve = resolveIPLocations) {}

  getSnapshot = (ip: string): IPLocationResult | undefined => this.entries.get(ip)?.result;

  subscribe(ip: string, listener: () => void) {
    if (!ip || ip === 'unknown' || ip.length > maxIPLocationInputLength) return () => {};
    let entry = this.entries.get(ip);
    if (!entry) {
      // 淘汰无人使用的缓存；极端大量可见地址时也不无限分配内存。
      if (this.entries.size >= cacheLimit) {
        const unused = [...this.entries].find(([, item]) => item.listeners.size === 0);
        if (unused) this.entries.delete(unused[0]);
        else return () => {};
      }
      entry = { nextAt: 0, listeners: new Set() };
      this.entries.set(ip, entry);
    }
    entry.listeners.add(listener);
    this.schedule();
    return () => {
      entry.listeners.delete(listener);
      if (![...this.entries.values()].some((item) => item.listeners.size)) {
        this.stopRequest();
      } else this.schedule();
    };
  }

  /** 保存配置后清空地点，旧请求即使晚到也不能覆盖新配置。 */
  invalidate() {
    this.stopRequest();
    for (const [ip, entry] of this.entries) {
      if (!entry.listeners.size) this.entries.delete(ip);
      else {
        entry.result = undefined;
        entry.nextAt = 0;
        entry.listeners.forEach((listener) => listener());
      }
    }
    this.schedule();
  }

  private stopRequest() {
    this.generation++;
    clearTimeout(this.timer);
    this.timer = undefined;
    this.request?.abort();
    this.request = undefined;
  }

  private schedule() {
    clearTimeout(this.timer);
    this.timer = undefined;
    if (this.request) return;
    const times = [...this.entries.values()].filter((entry) => entry.listeners.size).map((entry) => entry.nextAt);
    if (!times.length) return;
    // 短暂聚合本次渲染产生的订阅，避免每个表格单元格发起请求。
    this.timer = setTimeout(() => void this.flush(), Math.max(30, Math.min(...times) - Date.now()));
  }

  private async flush() {
    this.timer = undefined;
    const ips = [...this.entries].filter(([, entry]) => entry.listeners.size && entry.nextAt <= Date.now())
      .slice(0, batchLimit).map(([ip]) => ip);
    if (!ips.length) { this.schedule(); return; }
    const controller = new AbortController();
    const generation = this.generation;
    this.request = controller;
    try {
      const response = await this.resolve(ips, controller.signal);
      if (generation !== this.generation) return;
      if (!response.success || !Array.isArray(response.data?.items)) throw new Error('IP location unavailable');
      const results = new Map(response.data.items.map((item) => [item.ip, item]));
      for (const ip of ips) this.update(ip, results.get(ip) ?? { ip, status: 'failed' });
    } catch {
      if (generation === this.generation) {
        // 解析失败仅影响第二行说明，不触发业务页报错或全局消息。
        for (const ip of ips) this.update(ip, { ip, status: 'failed' });
      }
    } finally {
      if (this.request === controller) {
        this.request = undefined;
        this.schedule();
      }
    }
  }

  private update(ip: string, result: IPLocationResult) {
    const entry = this.entries.get(ip);
    if (!entry) return;
    entry.result = result;
    const delay = result.status === 'pending' ? 1000 : result.status === 'busy' ? 3000
      : result.status === 'failed' ? 15000 : result.status === 'disabled' ? 30000 : 60000;
    // 终态仍低频检查，其他管理员修改配置后最多一分钟刷新当前页面。
    entry.nextAt = Date.now() + delay;
    entry.listeners.forEach((listener) => listener());
  }
}

export const ipLocationClient = new IPLocationClient();
