/* 端到端验证：故障证据包模块
 * 运行：npm run verify:evidence
 * 覆盖：完整生成 / 缺失来源(分析、录波、来源晚于事件) / 封存后变化 / 重复创建稳定 / 指纹不一致
 */
import assert from 'node:assert/strict';
import { buildApp } from '../src/app.js';
import { analyses, audits, events, evidencePackages, recordings, topologyChanges } from '../src/domain/state.js';

const app = await buildApp();
const post = (url: string, body?: any) => app.inject({ method: 'POST', url, payload: body ?? {} });
const get = (url: string) => app.inject({ method: 'GET', url });

let passed = 0;
function check(name: string, fn: () => void) {
  fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

function makeRecording(name: string) {
  return post('/api/recordings', {
    name, lineId: 'L-AB', triggerTimeMs: 0, sampleRateHz: 1000,
    samples: [
      { timeMs: 0, channel: 'Ia', value: 12.4, unit: 'kA', quality: 'good' },
      { timeMs: 1, channel: 'Ib', value: 12.1, unit: 'kA', quality: 'good' },
      { timeMs: 1, channel: 'Ic', value: 11.9, unit: 'kA', quality: 'suspect' },
    ],
  }).then((r) => { assert.equal(r.statusCode, 200, `recording create: ${r.body}`); return r.json(); });
}

async function makeEventWithReplay(label: string, occurredAt: string, recordingId?: string) {
  const ev = (await post('/api/fault-events', {
    lineId: 'L-AB', type: 'three-phase', currentKa: 12.5, voltageKv: 220, occurredAt, source: `test-${label}`,
  })).json();
  if (recordingId) await post(`/api/fault-events/${ev.id}/replay`, { recordingId });
  else await post(`/api/fault-events/${ev.id}/replay`, {});
  return ev;
}

// ---------- 场景 1：完整生成 ----------
console.log('场景 1：完整证据包生成');
const rec1 = await makeRecording('录波-主场景');
// 事件时刻晚于录波入库时刻，保证来源不晚于事件
const occurredAt1 = new Date(Date.now() + 2000).toISOString();
const ev1 = await makeEventWithReplay('full', occurredAt1, rec1.id);

const gen1 = await post(`/api/fault-events/${ev1.id}/evidence-package`);
assert.equal(gen1.statusCode, 200, gen1.body);
assert.equal(gen1.headers['x-evidence-reused'], 'false');
const pkg1 = gen1.json();

check('返回包 id / 事件绑定 / 版本 / 初始状态', () => {
  assert.match(pkg1.id, /^ev-/);
  assert.equal(pkg1.eventId, ev1.id);
  assert.equal(pkg1.schemaVersion, '1.0');
  assert.equal(pkg1.status, 'generated');
});
check('内容按事件时刻截取：事件、录波、拓扑、定值、分析、审计六段齐全', () => {
  const c = pkg1.content;
  assert.equal(c.event.id, ev1.id);
  assert.equal(c.eventOccurredAt, occurredAt1);
  assert.equal(c.recordings.length, 1);
  assert.equal(c.recordings[0].id, rec1.id);
  assert.ok(c.recordings[0].samples.length === 3);
  assert.ok(Array.isArray(c.topology.substations) && c.topology.substations.length === 3);
  assert.ok(c.topology.lines.some((l: any) => l.id === 'L-AB'));
  assert.ok(c.topology.breakers.length >= 1);
  assert.ok(c.topology.devices.every((d: any) => d.lineId === 'L-AB'));
  assert.ok(c.settings.snapshots.length >= 1);
  assert.ok(c.settings.devices.some((d: any) => d.settingsVersion === 'set-2026.09'));
  assert.equal(c.analyses.length, 1);
  assert.equal(c.analyses[0].eventId, ev1.id);
  assert.ok(c.audits.some((a: any) => a.action === 'fault.create'));
  assert.ok(c.audits.some((a: any) => a.action === 'fault.replay'));
});
check('规范化只读内容带 SHA-256 总指纹与分段指纹', () => {
  assert.match(pkg1.fingerprints.content, /^sha256:[0-9a-f]{64}$/);
  assert.equal(pkg1.fingerprints.algorithm, 'sha256');
  for (const s of ['event', 'recordings', 'topology', 'settings', 'analyses', 'audits']) {
    assert.match(pkg1.fingerprints.sections[s], /^sha256:[0-9a-f]{64}$/, `section ${s}`);
  }
});
check('生成动作写入审计追踪', () => {
  assert.ok(audits.some((a) => a.action === 'evidence.generate' && a.entity === pkg1.id));
});

const v1 = (await post(`/api/evidence-packages/${pkg1.id}/verify`)).json();
check('未封存包校验：指纹一致、valid=true', () => {
  assert.equal(v1.fingerprintMatch, true);
  assert.equal(v1.sourceDrift, false);
  assert.equal(v1.valid, true);
});

const got = await get(`/api/evidence-packages/${pkg1.id}`);
check('可通过 id 取回证据包', () => assert.equal(got.json().id, pkg1.id));

// ---------- 场景 2：重复创建稳定 ----------
console.log('场景 2：重复创建必须稳定');
const gen1b = await post(`/api/fault-events/${ev1.id}/evidence-package`);
const pkg1b = gen1b.json();
check('重复生成返回同一个包（id/指纹不变，标记 reused）', () => {
  assert.equal(gen1b.headers['x-evidence-reused'], 'true');
  assert.equal(pkg1b.id, pkg1.id);
  assert.equal(pkg1b.fingerprints.content, pkg1.fingerprints.content);
  assert.equal(evidencePackages.filter((p) => p.eventId === ev1.id).length, 1);
});

// ---------- 场景 3：封存后源数据变化 ----------
console.log('场景 3：封存后源数据变化不能悄悄改包');
const seal = await post(`/api/evidence-packages/${pkg1.id}/seal`, { sealedBy: '值班调度-张工' });
assert.equal(seal.statusCode, 200, seal.body);
const sealedPkg = seal.json();
check('封存后状态为 sealed 并记录封存人/时刻', () => {
  assert.equal(sealedPkg.status, 'sealed');
  assert.equal(sealedPkg.sealedBy, '值班调度-张工');
  assert.ok(sealedPkg.sealedAt);
});
const vSealedClean = (await post(`/api/evidence-packages/${pkg1.id}/verify`)).json();
check('封存后、无变化时校验通过', () => {
  assert.equal(vSealedClean.sealed, true);
  assert.equal(vSealedClean.sourceDrift, false);
  assert.equal(vSealedClean.valid, true);
});

// 源数据变化：事件时刻前新增一条拓扑变更（当前内存拓扑发生后续变更）
const topBefore = topologyChanges.length;
await post('/api/topology/changes', {
  type: 'breaker-open', targetId: 'BR-B1', fromState: 'closed', toState: 'open',
  effectiveAt: new Date(new Date(occurredAt1).getTime() - 500).toISOString(), operator: '后续倒闸',
});
assert.equal(topologyChanges.length, topBefore + 1);

const livePkg = evidencePackages.find((p) => p.id === pkg1.id)!;
let freezeThrew = false;
try {
  (livePkg.content as any).event.fault.currentKa = 999;
} catch { freezeThrew = true; }
check('封存包深度冻结，直接改包被拒绝', () => assert.equal(freezeThrew, true));

const vDrift = (await post(`/api/evidence-packages/${pkg1.id}/verify`)).json();
const fetchedAfterDrift = (await get(`/api/evidence-packages/${pkg1.id}`)).json();
check('包内容/指纹保持封存时刻不变，但校验明确报告 topology 段来源漂移、valid=false', () => {
  assert.equal(vDrift.fingerprintMatch, true, '包自身指纹仍一致（未被悄悄改写）');
  assert.equal(vDrift.sourceDrift, true);
  assert.deepEqual(vDrift.sourceDriftSections, ['topology']);
  assert.equal(vDrift.valid, false);
  assert.equal(fetchedAfterDrift.fingerprints.content, pkg1.fingerprints.content);
  assert.equal(fetchedAfterDrift.content.event.fault.currentKa, 12.5);
  assert.ok(!fetchedAfterDrift.content.topology.asOfChanges.some((c: any) => c.operator === '后续倒闸'));
});

const gen1c = (await post(`/api/fault-events/${ev1.id}/evidence-package`)).json();
check('源变化后重复创建仍返回封存包而非重新截取', () => {
  assert.equal(gen1c.id, pkg1.id);
  assert.equal(gen1c.fingerprints.content, pkg1.fingerprints.content);
  assert.equal(gen1c.status, 'sealed');
});

const sealAgain = (await post(`/api/evidence-packages/${pkg1.id}/seal`, { sealedBy: '其他人' })).json();
check('重复封存幂等（封存人与时刻不变）', () => {
  assert.equal(sealAgain.sealedBy, '值班调度-张工');
  assert.equal(sealAgain.sealedAt, sealedPkg.sealedAt);
});

// ---------- 场景 4：缺失来源必须明确失败 ----------
console.log('场景 4：缺失来源 / 来源晚于事件必须明确失败');

// 4a. 事件不存在
const nf = await post('/api/fault-events/NO-SUCH-EVENT/evidence-package');
check('事件不存在 → 404 event-not-found', () => {
  assert.equal(nf.statusCode, 404);
  assert.equal(nf.json().code, 'event-not-found');
});

// 4b. 缺少分析
const evNoAnalysis = (await post('/api/fault-events', {
  lineId: 'L-AB', type: 'three-phase', occurredAt: new Date(Date.now() + 3000).toISOString(),
})).json();
const noAnalysis = await post(`/api/fault-events/${evNoAnalysis.id}/evidence-package`);
check('缺少分析 → 422 analysis-missing', () => {
  assert.equal(noAnalysis.statusCode, 422);
  assert.equal(noAnalysis.json().code, 'analysis-missing');
});

// 4c. 分析引用的录波不存在
const rec2 = await makeRecording('录波-稍后被移除');
const ev2 = await makeEventWithReplay('missing-rec', new Date(Date.now() + 4000).toISOString(), rec2.id);
const idx = recordings.findIndex((r) => r.id === rec2.id);
recordings.splice(idx, 1); // 模拟录波来源丢失
const recMissing = await post(`/api/fault-events/${ev2.id}/evidence-package`);
recordings.push(rec2); // 还原（不影响其它用例）
check('录波不存在 → 422 recording-missing 且指明缺失录波 id', () => {
  assert.equal(recMissing.statusCode, 422);
  assert.equal(recMissing.json().code, 'recording-missing');
  assert.equal(recMissing.json().details.recordingId, rec2.id);
});

// 4d. 来源（录波入库时刻）晚于事件时刻
const rec3 = await makeRecording('录波-晚于事件');
const ev3 = await makeEventWithReplay(
  'late-source',
  new Date(Date.now() - 10_000).toISOString(), // 事件发生在 10 秒前，录波此刻才入库
  rec3.id,
);
const late = await post(`/api/fault-events/${ev3.id}/evidence-package`);
check('来源晚于事件 → 422 source-after-event 且给出两个时间戳', () => {
  assert.equal(late.statusCode, 422);
  assert.equal(late.json().code, 'source-after-event');
  assert.equal(late.json().details.recordingId, rec3.id);
  assert.ok(late.json().details.sourceCreatedAt > late.json().details.eventOccurredAt);
});

// ---------- 场景 5：指纹不一致 ----------
console.log('场景 5：指纹不一致必须可检出');
const tampered = JSON.parse(JSON.stringify(livePkg));
tampered.id = 'ev-tampered-test';
tampered.content.event.fault.currentKa = 6.0; // 内容被改，指纹仍冒充原指纹
// 未冻结的伪造副本放入存储，模拟包被篡改
evidencePackages.push(tampered);
const vTampered = (await post('/api/evidence-packages/ev-tampered-test/verify')).json();
check('重算指纹与存档指纹不符 → fingerprintMatch=false、valid=false', () => {
  assert.equal(vTampered.fingerprintMatch, false);
  assert.notEqual(vTampered.recomputedFingerprint, vTampered.storedFingerprint);
  assert.equal(vTampered.valid, false);
});
const tamperedGet = await get('/api/evidence-packages/ev-tampered-test');
check('被篡改包仍可取回以便核验（服务不静默“修复”它）', () => {
  assert.equal(tamperedGet.statusCode, 200);
  assert.equal(tamperedGet.json().fingerprints.content, livePkg.fingerprints.content);
});

// ---------- 现有接口未被改变 ----------
console.log('场景 6：现有接口回归');
const trace = await get(`/api/fault-events/${ev1.id}/trace`);
check('故障 trace 仍返回事件与分析', () => {
  const body = trace.json();
  assert.equal(body.event.id, ev1.id);
  assert.ok(body.analyses.length >= 1);
});
const topo = await get('/api/grid/topology');
check('拓扑接口仍返回实时内存拓扑（topologyVersion 随变更增长）', () => {
  const body = topo.json();
  assert.ok(body.topologyVersion >= 1);
  assert.equal(body.substations.length, 3);
});
const approved = await post(`/api/analyses/${analyses.find((a) => a.eventId === ev1.id)!.id}/approve`, { approvedBy: 'test' });
check('分析审批接口仍可正常调用', () => assert.equal(approved.statusCode, 200));
const audit = await get('/api/audit');
check('审计接口包含故障、封存等完整追踪', () => {
  const list = audit.json();
  assert.ok(list.some((a: any) => a.action === 'evidence.seal'));
  assert.ok(list.some((a: any) => a.action === 'fault.create'));
});

console.log(`\n全部 ${passed} 项断言通过 ✅`);
await app.close();
process.exit(0);
