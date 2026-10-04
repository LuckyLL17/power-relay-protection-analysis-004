import { createHash } from 'node:crypto'; import { newId } from '../core/id.js'; import { analyses, audits, breakers, devices, evidencePackages, events, lines, log, now, recordings, settingSnapshots, substations, topologyChanges } from '../domain/state.js'; import type { EvidencePackage } from '../domain/types.js';

export function canonicalize(value: any): string { if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'; if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']'; const keys = Object.keys(value).filter(k => value[k] !== undefined).sort(); return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}'; }
export function fingerprintOf(content: any): string { return 'sha256:' + createHash('sha256').update(canonicalize(content)).digest('hex'); }
function deepFreeze<T>(value: T): T { if (value && typeof value === 'object') { for (const key of Object.keys(value as any)) deepFreeze((value as any)[key]); Object.freeze(value); } return value; }
const atMs = (iso: string) => Date.parse(iso);

export type SnapshotFailure = { status: number; error: string; detail: string };
export function buildSnapshot(eventId: string): { ok: true; snapshot: any; analysis: any; recording: any } | { ok: false; failure: SnapshotFailure } {
  const event = events.find(x => x.id === eventId);
  if (!event) return { ok: false, failure: { status: 404, error: 'fault-event-not-found', detail: `fault event ${eventId} not found` } };
  const related = analyses.filter(x => x.eventId === event.id);
  if (!related.length) return { ok: false, failure: { status: 409, error: 'missing-analysis', detail: `fault event ${event.id} has no replay analysis; run /api/fault-events/:id/replay first` } };
  const analysis = related[related.length - 1];
  if (!analysis.recordingId) return { ok: false, failure: { status: 409, error: 'missing-recording', detail: `analysis ${analysis.id} references no recording` } };
  const recording = recordings.find(x => x.id === analysis.recordingId);
  if (!recording) return { ok: false, failure: { status: 409, error: 'missing-recording', detail: `recording ${analysis.recordingId} referenced by analysis ${analysis.id} does not exist` } };
  const occurredAtMs = atMs(event.occurredAt);
  if (atMs(recording.createdAt) > occurredAtMs) return { ok: false, failure: { status: 409, error: 'source-after-event', detail: `recording ${recording.id} createdAt ${recording.createdAt} is later than event occurredAt ${event.occurredAt}` } };
  const lineDevices = devices.filter(x => x.lineId === event.lineId);
  const versions = [...new Set([...lineDevices.map(x => x.settingsVersion), analysis.settingsVersion].filter(Boolean))];
  const snapshots = settingSnapshots.filter(x => versions.includes(x.id));
  for (const s of snapshots) if (atMs(s.effectiveAt) > occurredAtMs) return { ok: false, failure: { status: 409, error: 'source-after-event', detail: `setting snapshot ${s.id} effectiveAt ${s.effectiveAt} is later than event occurredAt ${event.occurredAt}` } };
  const changesAtEvent = topologyChanges.filter(x => atMs(x.effectiveAt) <= occurredAtMs);
  const evidenceIds = new Set([event.id, analysis.id, recording.id]);
  const snapshot = structuredClone({
    event,
    analysis,
    recording,
    topologyAtEvent: { substations, lines, breakers, devices, changes: changesAtEvent, topologyVersion: changesAtEvent.length + 1 },
    settingsAtEvent: { devices: lineDevices, snapshots, missingSnapshotVersions: versions.filter(v => !snapshots.some(s => s.id === v)) },
    actionSequence: { events: analysis.events, sequence: analysis.sequence },
    audits: audits.filter(x => evidenceIds.has(x.entity))
  });
  return { ok: true, snapshot, analysis, recording };
}

export function sealPackage(eventId: string, sealedBy: string, handoverTo: string | null): { status: number; body: any } {
  const built = buildSnapshot(eventId);
  if (!built.ok) return { status: built.failure.status, body: { error: built.failure.error, detail: built.failure.detail } };
  const fingerprint = fingerprintOf(built.snapshot);
  const existing = evidencePackages.find(x => x.eventId === eventId);
  if (existing) {
    if (existing.fingerprint === fingerprint) return { status: 200, body: { ...existing, deduplicated: true } };
    return { status: 409, body: { error: 'sealed-source-drift', detail: 'source data changed after sealing; sealed package left untouched', packageId: existing.id, sealedFingerprint: existing.fingerprint, currentFingerprint: fingerprint } };
  }
  const pkg: EvidencePackage = { id: newId(), eventId, analysisId: built.analysis.id, recordingId: built.recording.id, status: 'sealed', algorithm: 'sha256', fingerprint, content: deepFreeze(built.snapshot), sealedAt: now(), sealedBy, handoverTo };
  evidencePackages.push(pkg);
  log('evidence.seal', pkg.id, { eventId, fingerprint, sealedBy });
  return { status: 201, body: pkg };
}

export function verifyPackage(packageId: string): { status: number; body: any } {
  const pkg = evidencePackages.find(x => x.id === packageId);
  if (!pkg) return { status: 404, body: { error: 'evidence-package-not-found', detail: `evidence package ${packageId} not found` } };
  const integrityOk = fingerprintOf(pkg.content) === pkg.fingerprint;
  const rebuilt = buildSnapshot(pkg.eventId);
  const sourceConsistent = rebuilt.ok ? fingerprintOf(rebuilt.snapshot) === pkg.fingerprint : null;
  const sourceError = rebuilt.ok ? null : rebuilt.failure.error;
  const verdict = !integrityOk ? 'tampered' : (sourceConsistent === false || sourceError) ? 'source-drift' : 'valid';
  log('evidence.verify', pkg.id, { verdict, integrityOk, sourceConsistent });
  return { status: 200, body: { packageId: pkg.id, eventId: pkg.eventId, fingerprint: pkg.fingerprint, integrityOk, sourceConsistent, sourceError, verdict, checkedAt: now() } };
}
