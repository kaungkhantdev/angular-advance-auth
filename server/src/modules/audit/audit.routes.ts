import { Router } from 'express';
import { z } from 'zod';
import { authenticate, requirePermission } from '../../middleware/auth.ts';
import { parse } from '../../middleware/errors.ts';
import { listAuditLogs } from './audit.service.ts';

export const auditRouter = Router();

auditRouter.get('/', authenticate, requirePermission('audit:read'), (req, res) => {
  const q = parse(z.object({
    limit: z.coerce.number().int().min(1).max(200).default(50),
    offset: z.coerce.number().int().min(0).default(0),
    actorId: z.uuid().optional(),
    action: z.string().trim().max(100).optional(),
  }), req.query);
  res.json(listAuditLogs(q));
});
