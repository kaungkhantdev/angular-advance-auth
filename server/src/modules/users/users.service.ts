import { db, tx } from '../../db/database.ts';
import { hashPassword, randomToken, uuid } from '../../lib/crypto.ts';
import { badRequest, conflict, forbidden, notFound } from '../../lib/errors.ts';
import { DEFAULT_ROLE, SUPER_ADMIN_ROLE } from '../../rbac/permissions.ts';
import { assertCanDelegate, isSuperAdmin, loadPrincipal, rolePermissions, type Principal } from '../../rbac/rbac.service.ts';
import { audit, type AuditContext } from '../audit/audit.service.ts';
import { findUserByEmail, findUserById, sendInvite } from '../auth/auth.service.ts';
import { revokeAllSessions } from '../auth/session.service.ts';

interface UserListRow {
  id: string;
  email: string;
  name: string;
  status: string;
  email_verified_at: number | null;
  mfa_enabled_at: number | null;
  locked_until: number | null;
  last_login_at: number | null;
  created_at: number;
  roles: string | null;
}

function toDto(r: UserListRow) {
  return {
    id: r.id,
    email: r.email,
    name: r.name,
    status: r.status,
    emailVerified: r.email_verified_at !== null,
    mfaEnabled: r.mfa_enabled_at !== null,
    locked: r.locked_until !== null && r.locked_until > Date.now(),
    lastLoginAt: r.last_login_at,
    createdAt: r.created_at,
    roles: r.roles ? r.roles.split(',').sort() : [],
  };
}

const SELECT_USER = `
  SELECT u.id, u.email, u.name, u.status, u.email_verified_at, u.mfa_enabled_at, u.locked_until,
         u.last_login_at, u.created_at,
         (SELECT GROUP_CONCAT(r.name) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id) AS roles
  FROM users u`;

export function listUsers(q: { search?: string; limit: number; offset: number }) {
  const where = q.search ? 'WHERE u.email LIKE ? OR u.name LIKE ?' : '';
  const params = q.search ? [`%${q.search}%`, `%${q.search}%`] : [];
  const total = (db.prepare(`SELECT COUNT(*) AS n FROM users u ${where}`).get(...params) as { n: number }).n;
  const items = (db.prepare(`${SELECT_USER} ${where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`)
    .all(...params, q.limit, q.offset) as unknown as UserListRow[]).map(toDto);
  return { total, items };
}

export function getUser(id: string) {
  const row = db.prepare(`${SELECT_USER} WHERE u.id = ?`).get(id) as UserListRow | undefined;
  if (!row) throw notFound('User');
  return toDto(row);
}

/**
 * Hierarchy rule: you may only manage accounts whose effective permissions are a
 * subset of your own. Prevents an admin from locking out, deleting or re-roling a
 * super admin (or anyone more privileged). Super admins may manage everyone.
 */
function assertCanManage(actor: Principal, targetId: string, action: string): void {
  if (!findUserById(targetId)) throw notFound('User');
  if (actor.userId === targetId) throw forbidden(`You cannot ${action} your own account here`);
  if (isSuperAdmin(actor)) return;
  const target = loadPrincipal(targetId);
  if ([...target.permissions].some((p) => !actor.permissions.has(p))) {
    throw forbidden(`You cannot ${action} a user with more privileges than you`);
  }
}

function countActiveSuperAdmins(): number {
  return (db.prepare(`
    SELECT COUNT(*) AS n FROM user_roles ur JOIN roles r ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id
    WHERE r.name = ? AND u.status = 'active'
  `).get(SUPER_ADMIN_ROLE) as { n: number }).n;
}

function assertNotLastSuperAdmin(targetId: string): void {
  if (loadPrincipal(targetId).roles.includes(SUPER_ADMIN_ROLE) && countActiveSuperAdmins() <= 1) {
    throw conflict('This is the last active super admin and cannot be removed or disabled');
  }
}

export async function createUser(
  actor: Principal, input: { email: string; name: string; roleIds: string[] }, ctx: AuditContext, actorName: string,
) {
  if (findUserByEmail(input.email)) throw conflict('A user with this e-mail already exists');
  const roleIds = input.roleIds.length ? input.roleIds : [defaultRoleId()];
  const roles = resolveRoles(roleIds);
  for (const r of roles) assertCanDelegate(actor, rolePermissions(r.id), r.name);

  const id = uuid();
  const now = Date.now();
  // Unusable random password until the invitee sets their own via the invite link.
  const placeholderHash = await hashPassword(randomToken(32));
  tx(() => {
    db.prepare(`
      INSERT INTO users (id, email, name, password_hash, email_verified_at, password_changed_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, NULL, ?, ?, ?)
    `).run(id, input.email, input.name, placeholderHash, now, now, now);
    const grant = db.prepare('INSERT INTO user_roles (user_id, role_id, granted_by, granted_at) VALUES (?, ?, ?, ?)');
    for (const r of roles) grant.run(id, r.id, actor.userId, now);
  });
  audit(ctx, { action: 'users.create', targetType: 'user', targetId: id, metadata: { roles: roles.map((r) => r.name) } });
  await sendInvite(id, actorName);
  return getUser(id);
}

export function updateUser(actor: Principal, id: string, input: { name?: string; status?: 'active' | 'disabled' }, ctx: AuditContext) {
  assertCanManage(actor, id, 'modify');
  const before = getUser(id);
  if (input.status === 'disabled' && before.status !== 'disabled') assertNotLastSuperAdmin(id);

  tx(() => {
    db.prepare('UPDATE users SET name = COALESCE(?, name), status = COALESCE(?, status), updated_at = ? WHERE id = ?')
      .run(input.name ?? null, input.status ?? null, Date.now(), id);
    if (input.status === 'disabled') revokeAllSessions(id, 'account_disabled');
  });
  audit(ctx, { action: 'users.update', targetType: 'user', targetId: id, metadata: { changes: input } });
  return getUser(id);
}

export function unlockUser(actor: Principal, id: string, ctx: AuditContext) {
  assertCanManage(actor, id, 'unlock');
  db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?').run(Date.now(), id);
  audit(ctx, { action: 'users.unlock', targetType: 'user', targetId: id });
  return getUser(id);
}

export function deleteUser(actor: Principal, id: string, ctx: AuditContext): void {
  assertCanManage(actor, id, 'delete');
  assertNotLastSuperAdmin(id);
  const { email } = getUser(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  audit(ctx, { action: 'users.delete', targetType: 'user', targetId: id, metadata: { email } });
}

/** Replaces the user's role set; every granted *and* revoked role must be delegable by the actor. */
export function setUserRoles(actor: Principal, id: string, roleIds: string[], ctx: AuditContext) {
  assertCanManage(actor, id, 'change roles of');
  const next = resolveRoles(roleIds);
  if (next.length === 0) throw badRequest('A user must have at least one role');

  const current = db.prepare('SELECT r.id, r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ?')
    .all(id) as { id: string; name: string }[];
  const nextIds = new Set(next.map((r) => r.id));
  const currentIds = new Set(current.map((r) => r.id));
  const added = next.filter((r) => !currentIds.has(r.id));
  const removed = current.filter((r) => !nextIds.has(r.id));

  for (const r of [...added, ...removed]) assertCanDelegate(actor, rolePermissions(r.id), r.name);
  if (removed.some((r) => r.name === SUPER_ADMIN_ROLE)) assertNotLastSuperAdmin(id);

  tx(() => {
    for (const r of removed) db.prepare('DELETE FROM user_roles WHERE user_id = ? AND role_id = ?').run(id, r.id);
    const grant = db.prepare('INSERT INTO user_roles (user_id, role_id, granted_by, granted_at) VALUES (?, ?, ?, ?)');
    for (const r of added) grant.run(id, r.id, actor.userId, Date.now());
  });
  audit(ctx, {
    action: 'users.roles_changed', targetType: 'user', targetId: id,
    metadata: { added: added.map((r) => r.name), removed: removed.map((r) => r.name) },
  });
  return getUser(id);
}

function resolveRoles(roleIds: string[]): { id: string; name: string }[] {
  const unique = [...new Set(roleIds)];
  if (unique.length === 0) return [];
  const rows = db.prepare(`SELECT id, name FROM roles WHERE id IN (${unique.map(() => '?').join(',')})`)
    .all(...unique) as { id: string; name: string }[];
  if (rows.length !== unique.length) throw badRequest('One or more roles do not exist');
  return rows;
}

function defaultRoleId(): string {
  return (db.prepare('SELECT id FROM roles WHERE name = ?').get(DEFAULT_ROLE) as { id: string }).id;
}
