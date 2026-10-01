import { db, tx } from '../../db/database.ts';
import { uuid } from '../../lib/crypto.ts';
import { badRequest, conflict, forbidden, notFound } from '../../lib/errors.ts';
import { SUPER_ADMIN_ROLE, type Permission } from '../../rbac/permissions.ts';
import { assertCanDelegate, permissionCatalog, rolePermissions, type Principal } from '../../rbac/rbac.service.ts';
import { audit, type AuditContext } from '../audit/audit.service.ts';

interface RoleRow {
  id: string;
  name: string;
  description: string;
  is_system: number;
  user_count: number;
  created_at: number;
  updated_at: number;
}

function toDto(r: RoleRow) {
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    /** Seeded from code: cannot be renamed or deleted, but its permissions can be edited. */
    isSystem: r.is_system === 1,
    /** Fully read-only (super_admin always holds every permission). */
    locked: r.is_system === 1 && r.name === SUPER_ADMIN_ROLE,
    userCount: r.user_count,
    permissions: rolePermissions(r.id).sort(),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

const SELECT_ROLE = `
  SELECT r.*, (SELECT COUNT(*) FROM user_roles ur WHERE ur.role_id = r.id) AS user_count FROM roles r`;

export function listPermissionCatalog() {
  return permissionCatalog();
}

export function listRoles() {
  return (db.prepare(`${SELECT_ROLE} ORDER BY r.is_system DESC, r.name`).all() as unknown as RoleRow[]).map(toDto);
}

export function getRole(id: string) {
  const row = db.prepare(`${SELECT_ROLE} WHERE r.id = ?`).get(id) as RoleRow | undefined;
  if (!row) throw notFound('Role');
  return toDto(row);
}

function assertEditable(role: ReturnType<typeof getRole>): void {
  // super_admin is re-synced to every permission on boot (see syncRbacCatalog).
  if (role.locked) throw forbidden('The super admin role always has every permission and cannot be modified');
}

export function createRole(actor: Principal, input: { name: string; description: string; permissions: Permission[] }, ctx: AuditContext) {
  if (db.prepare('SELECT 1 FROM roles WHERE name = ?').get(input.name)) throw conflict('A role with this name already exists');
  assertCanDelegate(actor, input.permissions);

  const id = uuid();
  const now = Date.now();
  tx(() => {
    db.prepare('INSERT INTO roles (id, name, description, is_system, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)')
      .run(id, input.name, input.description, now, now);
    setPermissions(id, input.permissions);
  });
  audit(ctx, { action: 'roles.create', targetType: 'role', targetId: id, metadata: { name: input.name, permissions: input.permissions } });
  return getRole(id);
}

export function updateRole(
  actor: Principal, id: string, input: { name?: string; description?: string; permissions?: Permission[] }, ctx: AuditContext,
) {
  const role = getRole(id);
  assertEditable(role);
  // Code looks system roles up by name (e.g. the default role for new sign-ups).
  if (role.isSystem && input.name && input.name !== role.name) throw forbidden('System roles cannot be renamed');
  if (input.name && input.name !== role.name && db.prepare('SELECT 1 FROM roles WHERE name = ?').get(input.name)) {
    throw conflict('A role with this name already exists');
  }

  let added: Permission[] = [];
  let removed: Permission[] = [];
  if (input.permissions) {
    const before = new Set(role.permissions);
    const after = new Set(input.permissions);
    added = input.permissions.filter((p) => !before.has(p));
    removed = role.permissions.filter((p) => !after.has(p));
    // Changing a role changes every holder's access, so the actor must hold every permission they touch.
    assertCanDelegate(actor, [...added, ...removed]);
  }

  tx(() => {
    db.prepare('UPDATE roles SET name = COALESCE(?, name), description = COALESCE(?, description), updated_at = ? WHERE id = ?')
      .run(input.name ?? null, input.description ?? null, Date.now(), id);
    if (input.permissions) setPermissions(id, input.permissions);
  });
  audit(ctx, { action: 'roles.update', targetType: 'role', targetId: id, metadata: { name: input.name, added, removed } });
  return getRole(id);
}

export function deleteRole(actor: Principal, id: string, ctx: AuditContext): void {
  const role = getRole(id);
  if (role.isSystem) throw forbidden('System roles cannot be deleted');
  assertCanDelegate(actor, role.permissions);
  if (role.userCount > 0) throw conflict(`Role is assigned to ${role.userCount} user(s) — unassign it first`);
  db.prepare('DELETE FROM roles WHERE id = ?').run(id);
  audit(ctx, { action: 'roles.delete', targetType: 'role', targetId: id, metadata: { name: role.name } });
}

function setPermissions(roleId: string, permissions: Permission[]): void {
  if (new Set(permissions).size !== permissions.length) throw badRequest('Duplicate permissions');
  db.prepare('DELETE FROM role_permissions WHERE role_id = ?').run(roleId);
  const add = db.prepare('INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = ?');
  for (const p of permissions) add.run(roleId, p);
}
