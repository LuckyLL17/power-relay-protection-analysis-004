import { createHash } from 'node:crypto';
import { newId } from '../core/id.js';
import {
  analyses, audits, breakers, devices, events, evidencePackages, lines, log, now, recordings,
  settingSnapshots, substations, topologyChanges,
} from '../domain/state.js';
import type {
  EvidencePackage, EvidencePackageContent, EvidencePackageStatus,
} from '../domain/types.js';

const SCHEMA_VERSION = '1.0' as const;
const FINGERPRINT_ALGORITHM = 'sha256' as const;

/** 证据包自身的生命周期动作不属于被截取的故障来源证据，两个快照构建路径一致排除。 */
const LIFECYCLE_ACTIONS = new Set(['evidence.generate', 'evidence.seal']);

export const EVIDENCE_SECTIONS = [
  'event', 'recordings', 'topology', 'settings', 'analyses', 'audits',
] as const;
export type EvidenceSection = (typeof EVIDENCE_SECTIONS)[number];

export class EvidenceError extends Error {
  constructor(public code: string, message: string, public details?: any) {
    super(message);
    this.name = 'EvidenceError';
  }
}

function sha256(canonical: string): string {
  return `${FINGERPRINT_ALGORITHM}:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

/** 规范化序列化：键按字典序排列，消除运行时对象差异，使指纹只取决于证据内容。 */
export function canonicalJson(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function clone<T>(v: T): T { return JSON.parse(JSON.stringify(v)) as T; }

function byTime<T extends Record<string, any>>(arr: T[], key: string): T[] {
  return [...arr].sort((a, b) => String(a[key]).localeCompare(String(b[key])) || String(a.id ?? '').localeCompare(String(b.id ?? '')));
}

/**
 * 按事件时刻截取证据快照。下列任一情况必须明确失败：
 *  - 事件不存在（event-not-found）
 *  - 该事件没有任何分析（analysis-missing）
 *  - 分析引用的录波不存在（recording-missing）
 *  - 录波来源时间晚于事件时刻（source-after-event）
 */
export function buildEvidenceContent(eventId: string): EvidencePackageContent {
  const event = events.find((x) => x.id === eventId);
  if (!event) throw new EvidenceError('event-not-found', `fault event not found: ${eventId}`, { eventId });

  const eventAnalyses = analyses.filter((x) => x.eventId === eventId);
  if (eventAnalyses.length === 0) {
    throw new EvidenceError('analysis-missing', `fault event has no analysis yet, cannot package: ${eventId}`, { eventId });
  }

  const eventOccurredAt = new Date(event.occurredAt).getTime();
  const referencedIds = Array.from(new Set(
    eventAnalyses.map((a) => a.recordingId).filter((id): id is string => Boolean(id)),
  ));
  const snapshotRecordings: any[] = [];
  for (const id of referencedIds) {
    const r = recordings.find((x) => x.id === id);
    if (!r) {
      throw new EvidenceError('recording-missing', `referenced recording does not exist: ${id}`, { eventId, recordingId: id });
    }
    if (new Date(r.createdAt).getTime() > eventOccurredAt) {
      throw new EvidenceError('source-after-event', `recording source ${id} is later than event ${eventId}`, {
        eventId, recordingId: id, eventOccurredAt: event.occurredAt, sourceCreatedAt: r.createdAt,
      });
    }
    snapshotRecordings.push(clone(r));
  }
  snapshotRecordings.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));

  // 事件时刻拓扑：只保留当时已生效（或无生效时间戳）的变更，快照为值拷贝
  const asOfChanges = byTime(
    topologyChanges.filter((c) => c.effectiveAt && new Date(c.effectiveAt).getTime() <= eventOccurredAt),
    'effectiveAt',
  ).map(clone);

  const relatedIds = new Set<string>([
    event.id,
    ...referencedIds,
    ...eventAnalyses.map((a) => a.id),
  ]);
  const auditRows = audits
    .filter((e) => !LIFECYCLE_ACTIONS.has(e.action))
    .filter((e) => relatedIds.has(e.entity) || relatedIds.has(e.payload?.id) || relatedIds.has(e.payload?.eventId))
    .map(clone)
    .sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));

  const lineDevices = devices.filter((d) => d.lineId === event.lineId).map(clone);

  return {
    schemaVersion: SCHEMA_VERSION,
    eventId: event.id,
    eventOccurredAt: event.occurredAt,
    event: clone(event),
    recordings: snapshotRecordings,
    topology: {
      substations: clone(substations),
      lines: clone(lines),
      breakers: clone(breakers),
      devices: lineDevices,
      asOfChanges,
    },
    settings: {
      devices: lineDevices,
      snapshots: clone(settingSnapshots),
    },
    analyses: byTime(eventAnalyses.map(clone), 'createdAt'),
    audits: auditRows,
  };
}

function sectionOf(content: EvidencePackageContent, section: EvidenceSection): unknown {
  return content[section];
}

export function computeFingerprints(content: EvidencePackageContent) {
  const sections = Object.fromEntries(
    EVIDENCE_SECTIONS.map((s) => [s, sha256(canonicalJson(sectionOf(content, s)))]),
  ) as Record<EvidenceSection, string>;
  return { algorithm: FINGERPRINT_ALGORITHM, content: sha256(canonicalJson(content)), sections };
}

function deepFreeze<T>(v: T): T {
  if (v === null || typeof v !== 'object') return v;
  Object.freeze(v);
  if (Array.isArray(v)) for (const item of v) deepFreeze(item);
  else for (const k of Object.keys(v as Record<string, any>)) deepFreeze((v as Record<string, any>)[k]);
  return v;
}

/** 重复创建稳定：同一事件已有证据包时原样返回（reused=true），不重新生成。 */
export function generateEvidencePackage(eventId: string): { pkg: EvidencePackage; reused: boolean } {
  const existing = evidencePackages.find((p) => p.eventId === eventId);
  if (existing) return { pkg: existing, reused: true };

  const content = buildEvidenceContent(eventId);
  const fingerprints = computeFingerprints(content);
  const pkg: EvidencePackage = {
    id: `ev-${newId()}`,
    eventId,
    schemaVersion: SCHEMA_VERSION,
    status: 'generated',
    createdAt: now(),
    content: deepFreeze(content),
    fingerprints,
  };
  evidencePackages.push(pkg);
  log('evidence.generate', pkg.id, {
    eventId: pkg.eventId,
    fingerprint: fingerprints.content,
    sectionFingerprints: fingerprints.sections,
    createdAt: pkg.createdAt,
  });
  return { pkg, reused: false };
}

export function sealEvidencePackage(pkgId: string, sealedBy = 'dispatch-protection'): EvidencePackage {
  const pkg = evidencePackages.find((p) => p.id === pkgId);
  if (!pkg) throw new EvidenceError('evidence-not-found', `evidence package not found: ${pkgId}`, { evidenceId: pkgId });
  if (pkg.status !== 'sealed') {
    pkg.status = 'sealed' satisfies EvidencePackageStatus;
    pkg.sealedAt = now();
    pkg.sealedBy = sealedBy;
    deepFreeze(pkg);
    log('evidence.seal', pkg.id, {
      eventId: pkg.eventId,
      sealedAt: pkg.sealedAt,
      sealedBy: pkg.sealedBy,
      fingerprint: pkg.fingerprints.content,
    });
  }
  return pkg;
}

export interface EvidenceVerification {
  evidenceId: string;
  eventId: string;
  status: EvidencePackageStatus;
  sealed: boolean;
  storedFingerprint: string;
  recomputedFingerprint: string | null;
  fingerprintMatch: boolean;
  sourceDrift: boolean | null;
  sourceDriftSections: EvidenceSection[];
  valid: boolean;
}

/**
 * 校验：
 *  1. 包内规范内容的 SHA-256 是否与存档指纹一致（防包被篡改）
 *  2. 封存后，按当前源数据重新截取的快照是否与封存快照逐段一致（封存后变化不能悄悄改包）
 */
export function verifyEvidencePackage(pkgId: string): EvidenceVerification {
  const pkg = evidencePackages.find((p) => p.id === pkgId);
  if (!pkg) throw new EvidenceError('evidence-not-found', `evidence package not found: ${pkgId}`, { evidenceId: pkgId });

  const recomputed = sha256(canonicalJson(pkg.content));
  const fingerprintMatch = recomputed === pkg.fingerprints.content;

  let sourceDrift: boolean | null = null;
  const driftSections: EvidenceSection[] = [];
  if (fingerprintMatch) {
    try {
      const fresh = buildEvidenceContent(pkg.eventId);
      const freshFp = computeFingerprints(fresh);
      for (const s of EVIDENCE_SECTIONS) {
        if (freshFp.sections[s] !== pkg.fingerprints.sections[s]) driftSections.push(s);
      }
      sourceDrift = driftSections.length > 0;
    } catch {
      // 源数据已缺失（如录波被移除），无法重建快照，视为来源不再可复现
      sourceDrift = null;
    }
  }

  return {
    evidenceId: pkg.id,
    eventId: pkg.eventId,
    status: pkg.status,
    sealed: pkg.status === 'sealed',
    storedFingerprint: pkg.fingerprints.content,
    recomputedFingerprint: recomputed,
    fingerprintMatch,
    sourceDrift,
    sourceDriftSections: driftSections,
    valid: fingerprintMatch && (pkg.status !== 'sealed' || sourceDrift === false),
  };
}
