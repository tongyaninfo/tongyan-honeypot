// 按同一时刻与客户端逐份对账，并用未分组的原始样本计算 P95。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const files = process.argv.slice(2);
if (!files.length || files.length % 2) {
  throw new Error('Usage: node compare-snapshot-benchmark.mjs before.json after.json [before2.json after2.json ...]');
}
const load = (path) => JSON.parse(readFileSync(path, 'utf8'));
const beforeRuns = files.filter((_, i) => i % 2 === 0).map(load);
const afterRuns = files.filter((_, i) => i % 2 === 1).map(load);
const targets = ['/api/v1/metrics/overview', '/api/v1/events?view=activity&page=1&pageSize=8'];
const stats = (values) => {
  const ordered = [...values].sort((a, b) => a - b);
  assert(ordered.length && ordered.every(Number.isFinite));
  const nearest = (p) => ordered[Math.ceil(p * ordered.length) - 1];
  return { n: ordered.length, p50: nearest(0.5), p95: nearest(0.95), max: nearest(1) };
};
const measures = (runs, route) => {
  const pick = (name) => runs.flatMap((run) => run[name].filter((s) => s.Route === route).map((s) => s.Milliseconds));
  const steady = pick('samples');
  const cold = pick('cold');
  return { steady: stats(steady), firstRequestMs: cold, includingFirst: stats([...steady, ...cold]) };
};
const commands = (runs, route) => {
  const queries = new Map();
  for (const run of runs) {
    for (const cmd of run.commands.filter((c) => c.Route === route.split('?')[0])) {
      const item = queries.get(cmd.Sql) ?? { sql: cmd.Sql, plan: cmd.plan, calls: 0, samples: [] };
      assert.deepEqual(item.plan, cmd.plan);
      item.samples.push(...cmd.byRound);
      item.calls += cmd.calls;
      queries.set(cmd.Sql, item);
    }
  }
  return [...queries.values()].map(({ samples, ...item }) => ({ ...item, perRequestMs: stats(samples) }))
    .sort((a, b) => b.perRequestMs.p95 - a.perRequestMs.p95);
};
const endpoints = {};
for (const route of targets) {
  let matched = 0;
  for (const [index, base] of beforeRuns.entries()) {
    const candidate = afterRuns[index];
    for (const key of ['clients', 'rounds', 'fromUtc']) assert.equal(base[key], candidate[key]);
    assert.equal(base.clients, beforeRuns[0].clients);
    const key = (s) => s.Round + '/' + s.Client;
    const select = (run) => [...run.cold, ...run.samples].filter((s) => s.Route === route);
    const expected = new Map(select(base).map((sample) => [key(sample), sample]));
    const actual = select(candidate);
    assert.equal(expected.size, base.clients * (base.rounds + 1));
    assert.equal(new Set(actual.map(key)).size, expected.size);
    assert.equal(actual.length, expected.size);
    for (const response of actual) {
      const old = expected.get(key(response));
      assert(old && old.Digest && response.Digest);
      assert.equal(old.Digest, response.Digest, route + ' ' + key(response));
      matched++;
    }
  }
  endpoints[route] = {
    matchedIncludingFirst: matched, before: measures(beforeRuns, route), after: measures(afterRuns, route),
    beforeSql: commands(beforeRuns, route), afterSql: commands(afterRuns, route),
  };
}
console.log(JSON.stringify({ clients: beforeRuns[0].clients, endpoints }, null, 2));
if (Object.values(endpoints).some((e) => e.after.includingFirst.p95 >= 1000)) process.exitCode = 1;
