import { Router } from 'express';
import { z } from 'zod';
import { authenticate, authOf, requirePermission } from '../../middleware/auth.ts';
import { parse } from '../../middleware/errors.ts';
import { clientContext } from '../../middleware/security.ts';
import { notFound } from '../../lib/errors.ts';
import { audit } from '../audit/audit.service.ts';
import { findUserById } from '../auth/auth.service.ts';
import { listActiveSessions, revokeAllSessions } from '../auth/session.service.ts';
import * as users from './users.service.ts';

export const usersRouter = Router();
usersRouter.use(authenticate);

const idParam = z.object({ id: z.uuid() });
const page = z.object({
  search: z.string().trim().max(100).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});

usersRouter.get('/', requirePermission('users:read'), (req, res) => {
  res.json(users.listUsers(parse(page, req.query)));
});

usersRouter.get('/:id', requirePermission('users:read'), (req, res) => {
  res.json(users.getUser(parse(idParam, req.params).id));
});

usersRouter.post('/', requirePermission('users:create'), async (req, res) => {
  const body = parse(z.object({
    email: z.email().max(254).transform((e) => e.trim().toLowerCase()),
    name: z.string().trim().min(1).max(100),
    roleIds: z.array(z.uuid()).max(20).default([]),
  }), req.body);
  const { principal, userId } = authOf(req);
  const actorName = findUserById(userId)?.name ?? 'An administrator';
  res.status(201).json(await users.createUser(principal, body, clientContext(req), actorName));
});

usersRouter.patch('/:id', requirePermission('users:update'), (req, res) => {
  const { id } = parse(idParam, req.params);
  const body = parse(z.object({
    name: z.string().trim().min(1).max(100).optional(),
    status: z.enum(['active', 'disabled']).optional(),
  }).strict(), req.body);
  res.json(users.updateUser(authOf(req).principal, id, body, clientContext(req)));
});

usersRouter.post('/:id/unlock', requirePermission('users:update'), (req, res) => {
  res.json(users.unlockUser(authOf(req).principal, parse(idParam, req.params).id, clientContext(req)));
});

usersRouter.delete('/:id', requirePermission('users:delete'), (req, res) => {
  users.deleteUser(authOf(req).principal, parse(idParam, req.params).id, clientContext(req));
  res.status(204).end();
});

usersRouter.put('/:id/roles', requirePermission('users:assign-roles'), (req, res) => {
  const { id } = parse(idParam, req.params);
  const { roleIds } = parse(z.object({ roleIds: z.array(z.uuid()).max(20) }), req.body);
  res.json(users.setUserRoles(authOf(req).principal, id, roleIds, clientContext(req)));
});

usersRouter.get('/:id/sessions', requirePermission('sessions:read'), (req, res) => {
  const { id } = parse(idParam, req.params);
  if (!findUserById(id)) throw notFound('User');
  res.json(listActiveSessions(id));
});

usersRouter.delete('/:id/sessions', requirePermission('sessions:revoke'), (req, res) => {
  const { id } = parse(idParam, req.params);
  if (!findUserById(id)) throw notFound('User');
  const count = revokeAllSessions(id, 'revoked_by_admin');
  audit(clientContext(req), { action: 'sessions.revoke_all', targetType: 'user', targetId: id, metadata: { count } });
  res.json({ revoked: count });
});
