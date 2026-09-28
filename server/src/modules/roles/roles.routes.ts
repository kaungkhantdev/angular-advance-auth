import { Router } from 'express';
import { z } from 'zod';
import { authenticate, authOf, requirePermission } from '../../middleware/auth.ts';
import { parse } from '../../middleware/errors.ts';
import { clientContext } from '../../middleware/security.ts';
import { isPermission, type Permission } from '../../rbac/permissions.ts';
import * as roles from './roles.service.ts';

export const rolesRouter = Router();
rolesRouter.use(authenticate);

const idParam = z.object({ id: z.uuid() });
const permissionList = z
  .array(z.string().refine(isPermission, 'Unknown permission'))
  .max(100)
  .transform((ps) => [...new Set(ps)] as Permission[]);
const roleName = z
  .string()
  .trim()
  .min(2)
  .max(50)
  .regex(/^[a-z][a-z0-9_-]*$/, 'Use lowercase letters, digits, "_" or "-"');

rolesRouter.get('/permissions', requirePermission('roles:read'), (_req, res) => {
  res.json(roles.listPermissionCatalog());
});

rolesRouter.get('/', requirePermission('roles:read'), (_req, res) => {
  res.json(roles.listRoles());
});

rolesRouter.get('/:id', requirePermission('roles:read'), (req, res) => {
  res.json(roles.getRole(parse(idParam, req.params).id));
});

rolesRouter.post('/', requirePermission('roles:create'), (req, res) => {
  const body = parse(z.object({
    name: roleName,
    description: z.string().trim().max(300).default(''),
    permissions: permissionList,
  }), req.body);
  res.status(201).json(roles.createRole(authOf(req).principal, body, clientContext(req)));
});

rolesRouter.patch('/:id', requirePermission('roles:update'), (req, res) => {
  const { id } = parse(idParam, req.params);
  const body = parse(z.object({
    name: roleName.optional(),
    description: z.string().trim().max(300).optional(),
    permissions: permissionList.optional(),
  }).strict(), req.body);
  res.json(roles.updateRole(authOf(req).principal, id, body, clientContext(req)));
});

rolesRouter.delete('/:id', requirePermission('roles:delete'), (req, res) => {
  roles.deleteRole(authOf(req).principal, parse(idParam, req.params).id, clientContext(req));
  res.status(204).end();
});
