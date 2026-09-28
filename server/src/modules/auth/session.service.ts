import { env } from '../../config/env.ts';
import { db, tx } from '../../db/database.ts';
import { randomToken, safeEqual, sha256, uuid } from '../../lib/crypto.ts';
import { AppError, unauthorized } from '../../lib/errors.ts';
import { audit } from '../audit/audit.service.ts';

/**
 * Refresh-token sessions with rotation and reuse detection (OAuth 2.0 Security BCP).
 *
 * - Every refresh issues a new token and invalidates the old one.
 * - Presenting an already-rotated token means it was stolen (or replayed), so the
 *   whole session is revoked — both the attacker and the victim are signed out.
 * - A short grace window tolerates the benign race where two browser tabs refresh
 *   simultaneously with the same cookie; the loser gets a retryable error instead.
 */
const RACE_GRACE_MS = 15_000;

interface SessionRow {
  id: string;
  user_id: string;
  token_hash: string;
  prev_token_hash: string | null;
  rotated_at: number | null;
  expires_at: number;
  absolute_expires_at: number;
  revoked_at: number | null;
  mfa_verified: number;
}

export interface IssuedSession {
  sessionId: string;
  userId: string;
  refreshToken: string;
  refreshExpiresAt: number;
}

export interface ClientInfo {
  ip?: string | null;
  userAgent?: string | null;
}

export function createSession(userId: string, client: ClientInfo, mfaVerified: boolean): IssuedSession {
  const now = Date.now();
  const id = uuid();
  const secret = randomToken();
  const absolute = now + env.SESSION_ABSOLUTE_TTL_SECONDS * 1000;
  const expires = Math.min(now + env.REFRESH_TOKEN_TTL_SECONDS * 1000, absolute);
  db.prepare(`
    INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, mfa_verified, created_at, last_used_at, expires_at, absolute_expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, userId, sha256(secret), client.ip ?? null, client.userAgent?.slice(0, 512) ?? null, mfaVerified ? 1 : 0, now, now, expires, absolute);
  return { sessionId: id, userId, refreshToken: `${id}.${secret}`, refreshExpiresAt: expires };
}

export function rotateSession(rawToken: string, client: ClientInfo): IssuedSession {
  const [sessionId, secret] = rawToken.split('.');
  if (!sessionId || !secret) throw unauthorized('Invalid refresh token', 'INVALID_REFRESH');

  // The transaction returns a failure instead of throwing, so revocations made while
  // rejecting the token are committed rather than rolled back.
  const outcome = tx((): IssuedSession | AppError => {
    const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as SessionRow | undefined;
    if (!s || s.revoked_at) return unauthorized('Session is no longer valid', 'INVALID_REFRESH');

    const now = Date.now();
    if (now >= s.expires_at || now >= s.absolute_expires_at) {
      revokeSession(s.id, 'expired');
      return unauthorized('Session expired — please sign in again', 'SESSION_EXPIRED');
    }

    const presented = sha256(secret);
    if (!safeEqual(presented, s.token_hash)) {
      if (s.prev_token_hash && safeEqual(presented, s.prev_token_hash) && s.rotated_at && now - s.rotated_at < RACE_GRACE_MS) {
        return unauthorized('Token was just rotated by a concurrent request — retry', 'REFRESH_RACE');
      }
      revokeSession(s.id, 'refresh_token_reuse');
      audit({ actorId: s.user_id, ...client }, {
        action: 'auth.refresh_token_reuse', targetType: 'session', targetId: s.id, success: false,
      });
      return unauthorized('Session revoked due to suspicious activity', 'REFRESH_REUSE');
    }

    const user = db.prepare('SELECT status FROM users WHERE id = ?').get(s.user_id) as { status: string } | undefined;
    if (!user || user.status !== 'active') {
      revokeSession(s.id, 'account_inactive');
      return unauthorized('Account is disabled', 'ACCOUNT_DISABLED');
    }

    const nextSecret = randomToken();
    const expires = Math.min(now + env.REFRESH_TOKEN_TTL_SECONDS * 1000, s.absolute_expires_at);
    db.prepare(`
      UPDATE sessions SET token_hash = ?, prev_token_hash = token_hash, rotated_at = ?, last_used_at = ?,
        expires_at = ?, ip = COALESCE(?, ip), user_agent = COALESCE(?, user_agent)
      WHERE id = ?
    `).run(sha256(nextSecret), now, now, expires, client.ip ?? null, client.userAgent?.slice(0, 512) ?? null, s.id);

    return { sessionId: s.id, userId: s.user_id, refreshToken: `${s.id}.${nextSecret}`, refreshExpiresAt: expires };
  });
  if (outcome instanceof AppError) throw outcome;
  return outcome;
}

/** Used on every authenticated request so logout / revocation is effective immediately. */
export function isSessionActive(sessionId: string, userId: string): boolean {
  const row = db
    .prepare('SELECT revoked_at, absolute_expires_at FROM sessions WHERE id = ? AND user_id = ?')
    .get(sessionId, userId) as { revoked_at: number | null; absolute_expires_at: number } | undefined;
  return !!row && row.revoked_at === null && Date.now() < row.absolute_expires_at;
}

export function sessionIdFromRefreshToken(raw: string | undefined): string | null {
  return raw?.split('.')[0] || null;
}

export function revokeSession(sessionId: string, reason: string): boolean {
  const r = db.prepare('UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE id = ? AND revoked_at IS NULL')
    .run(Date.now(), reason, sessionId);
  return r.changes > 0;
}

export function revokeUserSession(userId: string, sessionId: string, reason: string): boolean {
  const r = db.prepare('UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL')
    .run(Date.now(), reason, sessionId, userId);
  return r.changes > 0;
}

export function revokeAllSessions(userId: string, reason: string, exceptSessionId?: string): number {
  const r = db.prepare(`
    UPDATE sessions SET revoked_at = ?, revoked_reason = ?
    WHERE user_id = ? AND revoked_at IS NULL AND id != ?
  `).run(Date.now(), reason, userId, exceptSessionId ?? '');
  return Number(r.changes);
}

export function listActiveSessions(userId: string, currentSessionId?: string) {
  const rows = db.prepare(`
    SELECT id, ip, user_agent AS userAgent, mfa_verified AS mfaVerified, created_at AS createdAt,
           last_used_at AS lastUsedAt, expires_at AS expiresAt
    FROM sessions
    WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? AND absolute_expires_at > ?
    ORDER BY last_used_at DESC
  `).all(userId, Date.now(), Date.now()) as Array<{ id: string; mfaVerified: number } & Record<string, unknown>>;
  return rows.map((r) => ({ ...r, mfaVerified: r.mfaVerified === 1, current: r.id === currentSessionId }));
}
