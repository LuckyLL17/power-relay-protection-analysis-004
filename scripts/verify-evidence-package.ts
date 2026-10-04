import assert from 'node:assert/strict';
import { buildApp } from '../src/app.js';
import { evidencePackages, recordings } from '../src/domain/state.js';
import { fingerprintOf } from '../src/services/evidence-package.js';

const app = await buildApp();
const post = (url: string, body: any) => app.inject({ method: 'POST', url, payload: body });
const get = (url: string) => app.inject({ method: 'GET', url });
const sample = (t: number) => ({ timeMs: t, channel: 'Ia', value: 1.1 + t, unit: 'kA', quality: 'good' });

// 场景 1：完整生成 —— 录波 → 事件 → 重放 → 封存 → 校验
const rec = (await post('/api/recordings', { name: 'L-AB 故障录波', lineId: 'L-AB', samples: [sample(0), sample(1), sample(2)] })).json();
const ev = (await post('/api/fault-events', { lineId: 'L-AB', type: 'single-line-ground', currentKa: 8.2 })).json();
const ana = (await post(`/api/fault-events/${ev.id}/replay`, { recordingId: rec.id })).json();
const created = await post('/api/evidence-packages', { eventId: ev.id, sealedBy: 'dispatch-protection', handoverTo: 'relay-crew-2' });
assert.equal(created.statusCode, 201, 'create should seal');
const pkg = created.json();
assert.equal(pkg.status, 'sealed');
assert.match(pkg.fingerprint, /^sha256:[0-9a-f]{64}$/);
for (const section of ['event', 'analysis', 'recording', 'topologyAtEvent', 'settingsAtEvent', 'actionSequence', 'audits']) assert.ok(pkg.content[section], `section ${section} present`);
assert.equal(pkg.content.recording.samples.length, 3);
assert.equal(pkg.content.topologyAtEvent.topologyVersion, 1);
assert.equal(pkg.content.settingsAtEvent.snapshots[0].id, 'set-2026.09');
assert.ok(pkg.content.actionSequence.sequence.selectivity);
assert.deepEqual(pkg.content.audits.map((x: any) => x.action).sort(), ['fault.create', 'fault.replay', 'recording.ingest']);
assert.equal(fingerprintOf(pkg.content), pkg.fingerprint, 'fingerprint reproducible from content');
const v1 = (await post(`/api/evidence-packages/${pkg.id}/verify`, {})).json();
assert.deepEqual([v1.verdict, v1.integrityOk, v1.sourceConsistent], ['valid', true, true], 'fresh package verifies valid');
console.log('PASS 1 完整生成: sealed + fingerprint + 6 sections + verify valid');

// 场景 2：重复创建 —— 源数据未变时幂等，指纹稳定
const again = await post('/api/evidence-packages', { eventId: ev.id });
assert.equal(again.statusCode, 200);
assert.equal(again.json().id, pkg.id, 'same sealed package returned');
assert.equal(again.json().fingerprint, pkg.fingerprint, 'fingerprint stable across duplicate creation');
assert.equal(again.json().deduplicated, true);
assert.equal(evidencePackages.filter(x => x.eventId === ev.id).length, 1, 'no duplicate package stored');
console.log('PASS 2 重复创建: idempotent, same id + fingerprint, still one package');

// 场景 3：只读内容 —— 封存内容深冻结，进程内不可改
const stored = evidencePackages.find(x => x.id === pkg.id)!;
assert.throws(() => { (stored.content as any).event.status = 'hacked'; }, TypeError);
assert.throws(() => { (stored.content as any).recording.samples.push(sample(9)); }, TypeError);
console.log('PASS 3 只读内容: sealed content is deep-frozen');

// 场景 4：封存后源数据变化 —— 包不变，校验明确报漂移，重建被明确拒绝
recordings.find(x => x.id === rec.id)!.samples.push({ timeMs: 3, channel: 'Ia', value: 99, unit: 'kA', quality: 'bad' } as any);
const v2 = (await post(`/api/evidence-packages/${pkg.id}/verify`, {})).json();
assert.equal(v2.integrityOk, true, 'sealed package itself untouched');
assert.equal(v2.sourceConsistent, false, 'source drift detected');
assert.equal(v2.verdict, 'source-drift');
const afterDrift = (await get(`/api/evidence-packages/${pkg.id}`)).json();
assert.equal(afterDrift.content.recording.samples.length, 3, 'sealed content not silently altered');
assert.equal(afterDrift.fingerprint, pkg.fingerprint, 'sealed fingerprint unchanged');
const recreate = await post('/api/evidence-packages', { eventId: ev.id });
assert.equal(recreate.statusCode, 409);
assert.equal(recreate.json().error, 'sealed-source-drift');
assert.equal(recreate.json().sealedFingerprint, pkg.fingerprint);
assert.notEqual(recreate.json().currentFingerprint, pkg.fingerprint, '指纹不一致 explicitly reported');
assert.equal(evidencePackages.filter(x => x.eventId === ev.id).length, 1, 'drifted re-creation does not overwrite');
console.log('PASS 4 封存后变化 + 指纹不一致: verify=source-drift, re-create=409, package untouched');

// 场景 5：缺少分析 —— 未重放的事件明确失败
const evNoAna = (await post('/api/fault-events', { lineId: 'L-AB', type: 'three-phase' })).json();
const rNoAna = await post('/api/evidence-packages', { eventId: evNoAna.id });
assert.equal(rNoAna.statusCode, 409);
assert.equal(rNoAna.json().error, 'missing-analysis');
console.log('PASS 5 缺少分析: 409 missing-analysis');

// 场景 6：录波不存在 —— 重放未关联录波时明确失败
const evNoRec = (await post('/api/fault-events', { lineId: 'L-BC', type: 'three-phase' })).json();
await post(`/api/fault-events/${evNoRec.id}/replay`, {});
const rNoRec = await post('/api/evidence-packages', { eventId: evNoRec.id });
assert.equal(rNoRec.statusCode, 409);
assert.equal(rNoRec.json().error, 'missing-recording');
console.log('PASS 6 录波不存在: 409 missing-recording');

// 场景 7：来源晚于事件 —— 录波入库晚于事件发生时刻明确失败
const lateRec = (await post('/api/recordings', { name: '晚到录波', lineId: 'L-AB', samples: [sample(0)] })).json();
const evPast = (await post('/api/fault-events', { lineId: 'L-AB', type: 'three-phase', occurredAt: '2026-01-01T00:00:00.000Z' })).json();
await post(`/api/fault-events/${evPast.id}/replay`, { recordingId: lateRec.id });
const rLate = await post('/api/evidence-packages', { eventId: evPast.id });
assert.equal(rLate.statusCode, 409);
assert.equal(rLate.json().error, 'source-after-event');
assert.match(rLate.json().detail, /later than event occurredAt/);
console.log('PASS 7 来源晚于事件: 409 source-after-event');

// 场景 8：事件不存在
const rGone = await post('/api/evidence-packages', { eventId: 'no-such-event' });
assert.equal(rGone.statusCode, 404);
assert.equal((await post('/api/evidence-packages/no-such-pkg/verify', {})).statusCode, 404);
console.log('PASS 8 事件/包不存在: 404');

await app.close();
console.log('\n全部通过：完整生成 / 重复创建 / 只读封存 / 封存后变化 / 指纹不一致 / 缺少分析 / 录波不存在 / 来源晚于事件');
