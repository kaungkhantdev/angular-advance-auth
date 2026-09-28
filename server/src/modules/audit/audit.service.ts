import { db } from '../../db/database.ts';

export interface AuditContext {
  actorId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
}

export interface AuditEntry {
  action: string;
  targetType?: string;
  targetId?: string | null;
  success?: boolean;
  metadata?: Record<string, unknown>;
}

const insert = db.prepare(`
  INSERT INTO audit_logs (at, actor_id, action, target_type, target_id, success, ip, user_agent, metadata)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

/** Records a security-relevant event. Never put secrets (passwords, tokens, codes) in metadata. */
export function audit(ctx: AuditContext, entry: AuditEntry): void {
  insert.run(
    Date.now(),
    ctx.actorId ?? null,
    entry.action,
    entry.targetType ?? null,
    entry.targetId ?? null,
    entry.success === false ? 0 : 1,
    ctx.ip ?? null,
    ctx.userAgent?.slice(0, 512) ?? null,
    entry.metadata ? JSON.stringify(entry.metadata) : null,
  );
}

export interface AuditQuery {
  limit: number;
  offset: number;
  actorId?: string;
  action?: string;
}

export function listAuditLogs(q: AuditQuery) {
  const where: string[] = [];
  const params: (string | number)[] = [];
  if (q.actorId) { where.push('a.actor_id = ?'); params.push(q.actorId); }
  if (q.action) { where.push('a.action LIKE ?'); params.push(`${q.action}%`); }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const total = (db.prepare(`SELECT COUNT(*) AS n FROM audit_logs a ${clause}`).get(...params) as { n: number }).n;
  const rows = db
    .prepare(`
      SELECT a.id, a.at, a.actor_id AS actorId, u.email AS actorEmail, a.action, a.target_type AS targetType,
             a.target_id AS targetId, a.success, a.ip, a.user_agent AS userAgent, a.metadata
      FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
      ${clause}
      ORDER BY a.id DESC LIMIT ? OFFSET ?`)
    .all(...params, q.limit, q.offset) as Array<Record<string, unknown> & { success: number; metadata: string | null }>;

  return {
    total,
    items: rows.map((r) => ({ ...r, success: r.success === 1, metadata: r.metadata ? JSON.parse(r.metadata) : null })),
  };
}
