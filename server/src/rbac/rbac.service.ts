import { db, tx } from '../db/database.ts';
import { uuid } from '../lib/crypto.ts';
import { forbidden } from '../lib/errors.ts';
import { ALL_PERMISSIONS, isPermission, PERMISSION_DEFS, RESOURCES, SUPER_ADMIN_ROLE, SYSTEM_ROLES, type Permission } from './permissions.ts';

export interface Principal {
  userId: string;
  roles: string[];
  /** Effective permissions: everything granted by the user's roles, with implications expanded. */
  permissions: Set<Permission>;
}

/** Transitively follows permission_implications from a seed set (write ⇒ create ⇒ read …). */
const EXPAND = (seed: string) => `
  WITH RECURSIVE eff(p) AS (
    ${seed}
    UNION
    SELECT pi.implies FROM permission_implications pi JOIN eff ON pi.permission = eff.p
  )
  SELECT p FROM eff`;

const rolesStmt = db.prepare(`
  SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY r.name
`);
const userPermsStmt = db.prepare(EXPAND(`
  SELECT rp.permission FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id WHERE ur.user_id = ?`));
const rolePermsStmt = db.prepare(EXPAND('SELECT permission FROM role_permissions WHERE role_id = ?'));

const toPermissions = (rows: unknown[]) => (rows as { p: string }[]).map((r) => r.p).filter(isPermission);

/**
 * Resolved from the database on every request rather than baked into the JWT, so
 * role and implication changes take effect immediately (no stale-token window).
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

/** Permissions assigned directly to the role. */
export function rolePermissions(roleId: string): Permission[] {
  return (db.prepare('SELECT permission FROM role_permissions WHERE role_id = ?').all(roleId) as { permission: string }[])
    .map((r) => r.permission)
    .filter(isPermission);
}

/** Everything the role actually grants, implications included. */
export function roleEffectivePermissions(roleId: string): Permission[] {
  return toPermissions(rolePermsStmt.all(roleId)).sort();
}

export function expandPermissions(permissions: Iterable<Permission>): Set<Permission> {
  const seed = [...new Set(permissions)];
  if (seed.length === 0) return new Set();
  const rows = db.prepare(EXPAND(seed.map(() => 'SELECT ?').join(' UNION '))).all(...seed);
  return new Set(toPermissions(rows));
}

/**
 * Anti privilege-escalation rule: you can only hand out (or define a role with)
 * permissions you effectively hold yourself — including everything they imply.
 * The super_admin role can only be granted by a super admin.
 */
export function assertCanDelegate(actor: Principal, permissions: Iterable<Permission>, roleName?: string): void {
  if (roleName === SUPER_ADMIN_ROLE && !isSuperAdmin(actor)) {
    throw forbidden('Only a super admin can grant or revoke the super_admin role');
  }
  const missing = [...expandPermissions(permissions)].filter((p) => !actor.permissions.has(p));
  if (missing.length > 0) {
    throw forbidden(`You cannot delegate permissions you do not hold: ${missing.sort().join(', ')}`);
  }
}

/** The permission catalog as stored in the database, grouped by resource. */
export function permissionCatalog() {
  const rows = db.prepare(`
    SELECT p.name, p.resource, p.action, p.description,
           (SELECT GROUP_CONCAT(implies) FROM permission_implications WHERE permission = p.name) AS implies
    FROM permissions p ORDER BY p.rowid
  `).all() as { name: string; resource: string; action: string; description: string; implies: string | null }[];

  const labels: Record<string, string> = Object.fromEntries(Object.entries(RESOURCES).map(([k, v]) => [k, v.label]));
  const groups = new Map<string, { resource: string; label: string; permissions: unknown[] }>();
  for (const r of rows) {
    const group = groups.get(r.resource) ?? { resource: r.resource, label: labels[r.resource] ?? r.resource, permissions: [] };
    group.permissions.push({
      name: r.name,
      action: r.action,
      description: r.description,
      implies: r.implies ? r.implies.split(',').sort() : [],
      // Everything this permission grants, transitively — lets UIs show "included via write".
      grants: [...expandPermissions([r.name as Permission])].filter((p) => p !== r.name).sort(),
    });
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
 * Idempotently syncs the permission catalog, implications and system roles from
 * code into the DB. Runs at startup, so deploying new permissions needs no manual step.
 */
export function syncRbacCatalog(): void {
  tx(() => {
    const now = Date.now();
    const upsertPerm = db.prepare(`
      INSERT INTO permissions (name, description, resource, action) VALUES (?, ?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET description = excluded.description, resource = excluded.resource, action = excluded.action
    `);
    for (const p of PERMISSION_DEFS) upsertPerm.run(p.name, p.description, p.resource, p.action);

    // Remove permissions that no longer exist in code (cascades to role_permissions and implications).
    const known = new Set<string>(ALL_PERMISSIONS);
    for (const { name } of db.prepare('SELECT name FROM permissions').all() as { name: string }[]) {
      if (!known.has(name)) db.prepare('DELETE FROM permissions WHERE name = ?').run(name);
    }

    db.exec('DELETE FROM permission_implications');
    const addImplication = db.prepare('INSERT INTO permission_implications (permission, implies) VALUES (?, ?)');
    for (const p of PERMISSION_DEFS) for (const i of p.implies) addImplication.run(p.name, i);

    for (const [name, def] of Object.entries(SYSTEM_ROLES)) {
      let role = db.prepare('SELECT id FROM roles WHERE name = ?').get(name) as { id: string } | undefined;
      if (!role) {
        role = { id: uuid() };
        db.prepare('INSERT INTO roles (id, name, description, is_system, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)')
          .run(role.id, name, def.description, now, now);
      } else {
        db.prepare('UPDATE roles SET description = ?, is_system = 1 WHERE id = ?').run(def.description, role.id);
      }
      db.prepare('DELETE FROM role_permissions WHERE role_id = ?').run(role.id);
      const add = db.prepare('INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)');
      for (const p of def.permissions) add.run(role.id, p);
    }
  });
}
