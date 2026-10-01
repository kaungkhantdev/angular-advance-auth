import { db, tx } from '../db/database.ts';
import { uuid } from '../lib/crypto.ts';
import { forbidden } from '../lib/errors.ts';
import { ALL_PERMISSIONS, isPermission, PERMISSION_DEFS, RESOURCES, SUPER_ADMIN_ROLE, SYSTEM_ROLES, type Permission } from './permissions.ts';

export interface Principal {
  userId: string;
  roles: string[];
  /** Every permission granted by any of the user's roles. */
  permissions: Set<Permission>;
}

const rolesStmt = db.prepare(`
  SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY r.name
`);
const userPermsStmt = db.prepare(`
  SELECT DISTINCT p.name AS permission FROM user_roles ur
  JOIN role_permissions rp ON rp.role_id = ur.role_id
  JOIN permissions p ON p.id = rp.permission_id
  WHERE ur.user_id = ?`);

const toPermissions = (rows: unknown[]) => (rows as { permission: string }[]).map((r) => r.permission).filter(isPermission);

/**
 * Resolved from the database on every request rather than baked into the JWT, so
 * role changes take effect immediately (no stale-token window).
 */
export function loadPrincipal(userId: string): Principal {
  const roles = (rolesStmt.all(userId) as { name: string }[]).map((r) => r.name);
  return { userId, roles, permissions: new Set(toPermissions(userPermsStmt.all(userId))) };
}

export function hasPermission(principal: Principal, ...required: Permission[]): boolean {
  return required.every((p) => principal.permissions.has(p));
}

export function isSuperAdmin(principal: Principal): boolean {
  return principal.roles.includes(SUPER_ADMIN_ROLE);
}

/** The permissions the role grants. */
export function rolePermissions(roleId: string): Permission[] {
  return toPermissions(db.prepare(`
    SELECT p.name AS permission FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ?
  `).all(roleId));
}

/**
 * Anti privilege-escalation rule: you can only hand out (or define a role with)
 * permissions you hold yourself.
 * The super_admin role can only be granted by a super admin.
 */
export function assertCanDelegate(actor: Principal, permissions: Iterable<Permission>, roleName?: string): void {
  if (roleName === SUPER_ADMIN_ROLE && !isSuperAdmin(actor)) {
    throw forbidden('Only a super admin can grant or revoke the super_admin role');
  }
  const missing = [...new Set(permissions)].filter((p) => !actor.permissions.has(p));
  if (missing.length > 0) {
    throw forbidden(`You cannot delegate permissions you do not hold: ${missing.sort().join(', ')}`);
  }
}

/** The permission catalog as stored in the database, grouped by resource. */
export function permissionCatalog() {
  const rows = db.prepare('SELECT name, resource, action, description FROM permissions ORDER BY id')
    .all() as { name: string; resource: string; action: string; description: string }[];

  const labels: Record<string, string> = Object.fromEntries(Object.entries(RESOURCES).map(([k, v]) => [k, v.label]));
  const groups = new Map<string, { resource: string; label: string; permissions: unknown[] }>();
  for (const r of rows) {
    const group = groups.get(r.resource) ?? { resource: r.resource, label: labels[r.resource] ?? r.resource, permissions: [] };
    group.permissions.push({ name: r.name, action: r.action, description: r.description });
    groups.set(r.resource, group);
  }
  // Present in definition order (not DB insertion order); unknown resources last.
  const order = new Map(PERMISSION_DEFS.map((p, i) => [p.name as string, i]));
  const rank = (name: string) => order.get(name) ?? Number.MAX_SAFE_INTEGER;
  return [...groups.values()]
    .map((g) => ({ ...g, permissions: (g.permissions as { name: string }[]).sort((a, b) => rank(a.name) - rank(b.name)) }))
    .sort((a, b) => rank((a.permissions[0] as { name: string }).name) - rank((b.permissions[0] as { name: string }).name));
}

/**
 * Idempotently syncs the permission catalog from code into the DB and creates any
 * missing system roles. Runs at startup, so deploying new permissions needs no manual step.
 */
export function syncRbacCatalog(): void {
  tx(() => {
    const now = Date.now();
    const upsertPerm = db.prepare(`
      INSERT INTO permissions (name, description, resource, action) VALUES (?, ?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET description = excluded.description, resource = excluded.resource, action = excluded.action
    `);
    for (const p of PERMISSION_DEFS) upsertPerm.run(p.name, p.description, p.resource, p.action);

    // Remove permissions that no longer exist in code (cascades to role_permissions).
    const known = new Set<string>(ALL_PERMISSIONS);
    for (const { name } of db.prepare('SELECT name FROM permissions').all() as { name: string }[]) {
      if (!known.has(name)) db.prepare('DELETE FROM permissions WHERE name = ?').run(name);
    }

    // System roles get their code defaults only when first created; after that admins own
    // their permissions and description. super_admin is the exception: it always holds
    // every permission, including ones added in later deploys.
    const add = db.prepare('INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = ?');
    for (const [name, def] of Object.entries(SYSTEM_ROLES)) {
      let role = db.prepare('SELECT id FROM roles WHERE name = ?').get(name) as { id: string } | undefined;
      if (!role) {
        role = { id: uuid() };
        db.prepare('INSERT INTO roles (id, name, description, is_system, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)')
          .run(role.id, name, def.description, now, now);
        for (const p of def.permissions) add.run(role.id, p);
      } else {
        db.prepare('UPDATE roles SET is_system = 1 WHERE id = ?').run(role.id);
      }
      if (name === SUPER_ADMIN_ROLE) {
        db.prepare('UPDATE roles SET description = ? WHERE id = ?').run(def.description, role.id);
        db.prepare('DELETE FROM role_permissions WHERE role_id = ?').run(role.id);
        for (const p of def.permissions) add.run(role.id, p);
      }
    }
  });
}
