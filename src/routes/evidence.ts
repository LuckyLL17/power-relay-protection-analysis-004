import type { FastifyInstance, FastifyReply } from 'fastify';
import { events, evidencePackages } from '../domain/state.js';
import {
  EvidenceError, generateEvidencePackage, sealEvidencePackage, verifyEvidencePackage,
} from '../services/evidence-package.js';

function statusFor(code: string): number {
  if (code === 'evidence-not-found' || code === 'event-not-found') return 404;
  if (code === 'analysis-missing' || code === 'recording-missing' || code === 'source-after-event') return 422;
  return 400;
}

function fail(res: FastifyReply, err: unknown) {
  if (err instanceof EvidenceError) {
    return res.code(statusFor(err.code)).send({ error: err.message, code: err.code, details: err.details });
  }
  throw err;
}

export async function registerEvidenceRoutes(app: FastifyInstance) {
  // 生成（或取回已有的）故障证据包
  app.post('/api/fault-events/:id/evidence-package', async (req: any, res: any) => {
    try {
      const { pkg, reused } = generateEvidencePackage((req.params as any).id);
      res.header('X-Evidence-Reused', reused ? 'true' : 'false');
      return pkg;
    } catch (err) { return fail(res, err); }
  });

  app.get('/api/evidence-packages', async (req: any) => {
    const q = (req.query as any) || {};
    let list = evidencePackages;
    if (q.eventId) list = list.filter((p) => p.eventId === q.eventId);
    if (q.status) list = list.filter((p) => p.status === q.status);
    return list;
  });

  app.get('/api/evidence-packages/:id', async (req: any, res: any) => {
    const pkg = evidencePackages.find((p) => p.id === (req.params as any).id);
    if (!pkg) return res.code(404).send({ error: 'evidence package not found', code: 'evidence-not-found' });
    return pkg;
  });

  // 封存：封存后包被深度冻结，源数据变化只会在校验中暴露，不会改写包
  app.post('/api/evidence-packages/:id/seal', async (req: any, res: any) => {
    try {
      return sealEvidencePackage((req.params as any).id, (req.body as any)?.sealedBy);
    } catch (err) { return fail(res, err); }
  });

  // 校验：指纹一致性 + 封存后来源漂移检测
  app.post('/api/evidence-packages/:id/verify', async (req: any, res: any) => {
    try {
      return verifyEvidencePackage((req.params as any).id);
    } catch (err) { return fail(res, err); }
  });

  // 便捷入口：校验某事件当前绑定的证据包
  app.post('/api/fault-events/:id/evidence-package/verify', async (req: any, res: any) => {
    const event = events.find((x) => x.id === (req.params as any).id);
    if (!event) return res.code(404).send({ error: 'fault event not found', code: 'event-not-found' });
    const pkg = evidencePackages.find((p) => p.eventId === event.id);
    if (!pkg) return res.code(404).send({ error: 'evidence package not found', code: 'evidence-not-found' });
    try {
      return verifyEvidencePackage(pkg.id);
    } catch (err) { return fail(res, err); }
  });
}
