import { randomInt } from 'node:crypto';
import QRCode from 'qrcode';
import { env } from '../../config/env.ts';
import { db, tx } from '../../db/database.ts';
import {
  decrypt, DUMMY_PASSWORD_HASH, encrypt, hashPassword, needsRehash, randomToken, sha256, uuid, verifyPassword,
} from '../../lib/crypto.ts';
import { AppError, badRequest, locked, unauthorized } from '../../lib/errors.ts';
import { mailer } from '../../lib/mailer.ts';
import { passwordContainsIdentity } from '../../lib/password-policy.ts';
import { generateTotpSecret, totpUri, verifyTotp } from '../../lib/totp.ts';
import { DEFAULT_ROLE } from '../../rbac/permissions.ts';
import { loadPrincipal } from '../../rbac/rbac.service.ts';
import { audit, type AuditContext } from '../audit/audit.service.ts';
import { createSession, revokeAllSessions, revokeSession, rotateSession, type ClientInfo } from './session.service.ts';
import { signAccessToken, signMfaChallenge, verifyMfaChallenge } from './token.service.ts';

export const MAX_FAILED_ATTEMPTS = 5;
export const LOCKOUT_MS = 15 * 60_000;
const VERIFY_EMAIL_TTL_MS = 24 * 3600_000;
const RESET_PASSWORD_TTL_MS = 30 * 60_000;
const INVITE_TTL_MS = 72 * 3600_000;
const RECOVERY_CODE_COUNT = 10;
const MFA_ISSUER = 'Advance Auth';
/** Unambiguous lowercase alphabet (no 0/o/1/l/i): 10 chars ≈ 49 bits of entropy. */
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

export interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  status: 'active' | 'disabled';
  email_verified_at: number | null;
  failed_login_attempts: number;
  locked_until: number | null;
  mfa_secret_enc: string | null;
  mfa_pending_secret_enc: string | null;
  mfa_enabled_at: number | null;
  mfa_last_used_step: number | null;
  created_at: number;
}

const byEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const byId = db.prepare('SELECT * FROM users WHERE id = ?');

export const findUserByEmail = (email: string) => byEmail.get(email.trim()) as UserRow | undefined;
export const findUserById = (id: string) => byId.get(id) as UserRow | undefined;

/** The authenticated user's own view: identity + effective roles and permissions. */
export function currentUser(userId: string) {
  const u = findUserById(userId);
  if (!u) throw unauthorized();
  const principal = loadPrincipal(userId);
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    emailVerified: u.email_verified_at !== null,
    mfaEnabled: u.mfa_enabled_at !== null,
    roles: principal.roles,
    permissions: [...principal.permissions].sort(),
    createdAt: u.created_at,
  };
}

export interface AuthResult {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresAt: number;
  user: ReturnType<typeof currentUser>;
}

async function issueTokens(userId: string, client: ClientInfo, mfaVerified: boolean): Promise<AuthResult> {
  const session = createSession(userId, client, mfaVerified);
  db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?')
    .run(Date.now(), userId);
  const { token, expiresIn } = await signAccessToken(userId, session.sessionId);
  return {
    accessToken: token,
    expiresIn,
    refreshToken: session.refreshToken,
    refreshExpiresAt: session.refreshExpiresAt,
    user: currentUser(userId),
  };
}

// ----------------------------------------------------------------------------
// Registration & e-mail verification
// ----------------------------------------------------------------------------

export async function register(input: { email: string; name: string; password: string }, ctx: AuditContext): Promise<void> {
  const email = input.email.trim().toLowerCase();
  if (passwordContainsIdentity(input.password, email, input.name)) {
    throw badRequest('Password must not contain your name or e-mail');
  }

  // Hash before the existence check so both paths take the same time.
  const passwordHash = await hashPassword(input.password);

  const existing = findUserByEmail(email);
  if (existing) {
    // Don't reveal that the account exists — respond identically and tell the real owner instead.
    await mailer.send({
      to: email,
      subject: 'Sign-up attempt on your account',
      text: `Someone tried to create an account with this e-mail. If it was you, sign in or reset your password at ${env.APP_URL}/forgot-password.`,
    });
    audit(ctx, { action: 'auth.register_duplicate', targetType: 'user', targetId: existing.id, success: false });
    return;
  }

  const id = uuid();
  const now = Date.now();
  tx(() => {
    db.prepare(`
      INSERT INTO users (id, email, name, password_hash, password_changed_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, email, input.name.trim(), passwordHash, now, now, now);
    db.prepare(`INSERT INTO user_roles (user_id, role_id, granted_at) SELECT ?, id, ? FROM roles WHERE name = ?`)
      .run(id, now, DEFAULT_ROLE);
  });
  audit({ ...ctx, actorId: id }, { action: 'auth.register', targetType: 'user', targetId: id });
  await sendVerificationEmail(id, email);
}

function createOneTimeToken(userId: string, purpose: 'verify_email' | 'reset_password', ttlMs: number): string {
  const token = randomToken();
  const now = Date.now();
  tx(() => {
    // Only the most recent link is valid.
    db.prepare('UPDATE one_time_tokens SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL')
      .run(now, userId, purpose);
    db.prepare('INSERT INTO one_time_tokens (id, user_id, purpose, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(uuid(), userId, purpose, sha256(token), now + ttlMs, now);
  });
  return token;
}

/** Atomically consumes a token; returns its user id or throws. */
function consumeOneTimeToken(token: string, purpose: 'verify_email' | 'reset_password'): string {
  const now = Date.now();
  const row = db.prepare(`
    UPDATE one_time_tokens SET used_at = ?
    WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
    RETURNING user_id
  `).get(now, sha256(token), purpose, now) as { user_id: string } | undefined;
  if (!row) throw badRequest('This link is invalid or has expired');
  return row.user_id;
}

async function sendVerificationEmail(userId: string, email: string): Promise<void> {
  const token = createOneTimeToken(userId, 'verify_email', VERIFY_EMAIL_TTL_MS);
  await mailer.send({
    to: email,
    subject: 'Verify your e-mail address',
    text: `Confirm your e-mail address: ${env.APP_URL}/verify-email?token=${token}\nThis link expires in 24 hours.`,
  });
}

export function verifyEmail(token: string, ctx: AuditContext): void {
  const userId = consumeOneTimeToken(token, 'verify_email');
  db.prepare('UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?), updated_at = ? WHERE id = ?')
    .run(Date.now(), Date.now(), userId);
  audit({ ...ctx, actorId: userId }, { action: 'auth.email_verified', targetType: 'user', targetId: userId });
}

export async function resendVerification(email: string): Promise<void> {
  const user = findUserByEmail(email);
  if (user && !user.email_verified_at && user.status === 'active') await sendVerificationEmail(user.id, user.email);
}

// ----------------------------------------------------------------------------
// Login (password → optional TOTP) with account lockout
// ----------------------------------------------------------------------------

export type LoginResult = { mfaRequired: true; mfaToken: string } | ({ mfaRequired: false } & AuthResult);

const INVALID_CREDENTIALS = () => unauthorized('Invalid email or password', 'INVALID_CREDENTIALS');

function assertNotLocked(user: UserRow): void {
  if (user.locked_until && user.locked_until > Date.now()) {
    const minutes = Math.ceil((user.locked_until - Date.now()) / 60_000);
    throw locked(`Too many failed attempts. Try again in ${minutes} minute(s) or reset your password.`);
  }
}

async function registerFailure(user: UserRow, ctx: AuditContext, reason: string): Promise<void> {
  const attempts = user.failed_login_attempts + 1;
  const lockNow = attempts >= MAX_FAILED_ATTEMPTS;
  db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?')
    .run(lockNow ? 0 : attempts, lockNow ? Date.now() + LOCKOUT_MS : null, user.id);
  audit(ctx, { action: 'auth.login_failed', targetType: 'user', targetId: user.id, success: false, metadata: { reason, attempts } });
  if (lockNow) {
    audit(ctx, { action: 'auth.account_locked', targetType: 'user', targetId: user.id, success: false });
    await mailer.send({
      to: user.email,
      subject: 'Your account was temporarily locked',
      text: `We locked your account for ${LOCKOUT_MS / 60_000} minutes after ${MAX_FAILED_ATTEMPTS} failed sign-in attempts from IP ${ctx.ip ?? 'unknown'}.\nIf this wasn't you, reset your password: ${env.APP_URL}/forgot-password`,
    });
  }
}

export async function login(input: { email: string; password: string }, client: ClientInfo): Promise<LoginResult> {
  const ctx: AuditContext = { ...client };
  const user = findUserByEmail(input.email);

  if (!user) {
    await verifyPassword(input.password, DUMMY_PASSWORD_HASH); // uniform timing
    audit(ctx, { action: 'auth.login_failed', success: false, metadata: { reason: 'unknown_email' } });
    throw INVALID_CREDENTIALS();
  }

  assertNotLocked(user);

  if (!(await verifyPassword(input.password, user.password_hash))) {
    await registerFailure(user, ctx, 'bad_password');
    throw INVALID_CREDENTIALS();
  }

  // Only reveal account state once the caller has proven they know the password.
  if (user.status !== 'active') throw new AppError(403, 'ACCOUNT_DISABLED', 'This account has been disabled');
  if (!user.email_verified_at) {
    throw new AppError(403, 'EMAIL_NOT_VERIFIED', 'Please verify your e-mail address before signing in');
  }

  if (needsRehash(user.password_hash)) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await hashPassword(input.password), user.id);
  }

  if (user.mfa_enabled_at) {
    audit({ ...ctx, actorId: user.id }, { action: 'auth.mfa_challenge_issued', targetType: 'user', targetId: user.id });
    return { mfaRequired: true, mfaToken: await signMfaChallenge(user.id) };
  }

  const result = await issueTokens(user.id, client, false);
  audit({ ...ctx, actorId: user.id }, { action: 'auth.login', targetType: 'user', targetId: user.id });
  return { mfaRequired: false, ...result };
}

export async function completeMfaLogin(input: { mfaToken: string; code: string }, client: ClientInfo): Promise<AuthResult> {
  const userId = await verifyMfaChallenge(input.mfaToken);
  const user = findUserById(userId);
  if (!user || !user.mfa_secret_enc || user.status !== 'active') throw unauthorized('MFA challenge invalid', 'MFA_CHALLENGE_INVALID');
  const ctx: AuditContext = { ...client, actorId: user.id };

  // Failures on the second factor count toward the same lockout as passwords.
  assertNotLocked(user);
  const method = verifySecondFactor(user, input.code);
  if (!method) {
    await registerFailure(user, ctx, 'bad_mfa_code');
    throw unauthorized('Invalid authentication code', 'INVALID_MFA_CODE');
  }

  const result = await issueTokens(user.id, client, true);
  audit(ctx, { action: 'auth.login', targetType: 'user', targetId: user.id, metadata: { mfa: method } });
  return result;
}

/** Accepts a TOTP code or a one-time recovery code. Returns the method used, or null. */
function verifySecondFactor(user: UserRow, rawCode: string): 'totp' | 'recovery_code' | null {
  const code = rawCode.replace(/[\s-]/g, '');
  if (/^\d{6}$/.test(code)) {
    const step = verifyTotp(decrypt(user.mfa_secret_enc!), code, user.mfa_last_used_step);
    if (step === null) return null;
    db.prepare('UPDATE users SET mfa_last_used_step = ? WHERE id = ?').run(step, user.id);
    return 'totp';
  }
  const used = db.prepare(`
    UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL RETURNING id
  `).get(Date.now(), user.id, sha256(code.toLowerCase()));
  return used ? 'recovery_code' : null;
}

// ----------------------------------------------------------------------------
// Session lifecycle
// ----------------------------------------------------------------------------

export async function refresh(rawToken: string | undefined, client: ClientInfo): Promise<AuthResult> {
  if (!rawToken) throw unauthorized('No session', 'NO_REFRESH_TOKEN');
  const session = rotateSession(rawToken, client);
  const { token, expiresIn } = await signAccessToken(session.userId, session.sessionId);
  return {
    accessToken: token,
    expiresIn,
    refreshToken: session.refreshToken,
    refreshExpiresAt: session.refreshExpiresAt,
    user: currentUser(session.userId),
  };
}

export function logout(sessionId: string | null, ctx: AuditContext): void {
  if (sessionId && revokeSession(sessionId, 'logout')) {
    audit(ctx, { action: 'auth.logout', targetType: 'session', targetId: sessionId });
  }
}

// ----------------------------------------------------------------------------
// Password management
// ----------------------------------------------------------------------------

export async function forgotPassword(email: string, ctx: AuditContext): Promise<void> {
  const user = findUserByEmail(email);
  // Same response whether or not the account exists.
  if (!user || user.status !== 'active') return;
  const token = createOneTimeToken(user.id, 'reset_password', RESET_PASSWORD_TTL_MS);
  audit({ ...ctx, actorId: user.id }, { action: 'auth.password_reset_requested', targetType: 'user', targetId: user.id });
  await mailer.send({
    to: user.email,
    subject: 'Reset your password',
    text: `Reset your password: ${env.APP_URL}/reset-password?token=${token}\nThis link expires in 30 minutes. If you didn't ask for this, ignore this e-mail.`,
  });
}

/** Admin-created accounts get a "set your password" link instead of a password chosen by someone else. */
export async function sendInvite(userId: string, invitedBy: string): Promise<void> {
  const user = findUserById(userId);
  if (!user) return;
  const token = createOneTimeToken(user.id, 'reset_password', INVITE_TTL_MS);
  await mailer.send({
    to: user.email,
    subject: "You've been invited to Advance Auth",
    text: `${invitedBy} created an account for you. Choose your password: ${env.APP_URL}/reset-password?token=${token}\nThis link expires in 72 hours.`,
  });
}

export async function resetPassword(input: { token: string; password: string }, ctx: AuditContext): Promise<void> {
  // Validate identity rules before burning the token, so a rejected password doesn't invalidate the link.
  const peek = db.prepare(`
    SELECT u.email, u.name FROM one_time_tokens t JOIN users u ON u.id = t.user_id
    WHERE t.token_hash = ? AND t.purpose = 'reset_password' AND t.used_at IS NULL AND t.expires_at > ?
  `).get(sha256(input.token), Date.now()) as { email: string; name: string } | undefined;
  if (peek && passwordContainsIdentity(input.password, peek.email, peek.name)) {
    throw badRequest('Password must not contain your name or e-mail');
  }

  const hash = await hashPassword(input.password);
  const userId = tx(() => {
    const id = consumeOneTimeToken(input.token, 'reset_password');
    const now = Date.now();
    // Resetting via e-mail also proves ownership of the address and clears any lockout.
    db.prepare(`
      UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ?, failed_login_attempts = 0,
        locked_until = NULL, email_verified_at = COALESCE(email_verified_at, ?)
      WHERE id = ?
    `).run(hash, now, now, now, id);
    revokeAllSessions(id, 'password_reset');
    return id;
  });
  audit({ ...ctx, actorId: userId }, { action: 'auth.password_reset', targetType: 'user', targetId: userId });
  const user = findUserById(userId)!;
  await mailer.send({ to: user.email, subject: 'Your password was changed', text: 'Your password was reset and all devices were signed out. If this wasn\'t you, contact support immediately.' });
}

export async function changePassword(
  userId: string, currentSessionId: string, input: { currentPassword: string; newPassword: string }, ctx: AuditContext,
): Promise<void> {
  const user = findUserById(userId);
  if (!user) throw unauthorized();
  if (!(await verifyPassword(input.currentPassword, user.password_hash))) {
    audit(ctx, { action: 'auth.password_change_failed', targetType: 'user', targetId: userId, success: false });
    throw badRequest('Current password is incorrect');
  }
  if (input.currentPassword === input.newPassword) throw badRequest('New password must differ from the current one');
  if (passwordContainsIdentity(input.newPassword, user.email, user.name)) throw badRequest('Password must not contain your name or e-mail');

  const now = Date.now();
  db.prepare('UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?')
    .run(await hashPassword(input.newPassword), now, now, userId);
  const revoked = revokeAllSessions(userId, 'password_changed', currentSessionId);
  audit(ctx, { action: 'auth.password_changed', targetType: 'user', targetId: userId, metadata: { otherSessionsRevoked: revoked } });
  await mailer.send({ to: user.email, subject: 'Your password was changed', text: 'Your password was changed and your other devices were signed out. If this wasn\'t you, reset your password immediately.' });
}

/** Step-up check for sensitive operations: the user must re-enter their password. */
async function requirePasswordConfirmation(user: UserRow, password: string, ctx: AuditContext, action: string): Promise<void> {
  if (!(await verifyPassword(password, user.password_hash))) {
    audit(ctx, { action, targetType: 'user', targetId: user.id, success: false, metadata: { reason: 'bad_password' } });
    throw badRequest('Password is incorrect');
  }
}

// ----------------------------------------------------------------------------
// MFA (TOTP) enrolment
// ----------------------------------------------------------------------------

export async function startMfaSetup(userId: string, password: string, ctx: AuditContext) {
  const user = findUserById(userId);
  if (!user) throw unauthorized();
  if (user.mfa_enabled_at) throw badRequest('Two-factor authentication is already enabled');
  await requirePasswordConfirmation(user, password, ctx, 'auth.mfa_setup_started');

  const secret = generateTotpSecret();
  db.prepare('UPDATE users SET mfa_pending_secret_enc = ? WHERE id = ?').run(encrypt(secret), userId);
  const uri = totpUri(secret, user.email, MFA_ISSUER);
  return { secret, otpauthUrl: uri, qrCodeDataUrl: await QRCode.toDataURL(uri) };
}

export function confirmMfaSetup(userId: string, currentSessionId: string, code: string, ctx: AuditContext): { recoveryCodes: string[] } {
  const user = findUserById(userId);
  if (!user?.mfa_pending_secret_enc) throw badRequest('Start two-factor setup first');
  const step = verifyTotp(decrypt(user.mfa_pending_secret_enc), code.replace(/\s/g, ''), null);
  if (step === null) throw badRequest('Invalid code — check your authenticator app and device clock');

  const recoveryCodes = tx(() => {
    db.prepare(`
      UPDATE users SET mfa_secret_enc = mfa_pending_secret_enc, mfa_pending_secret_enc = NULL,
        mfa_enabled_at = ?, mfa_last_used_step = ?, updated_at = ?
      WHERE id = ?
    `).run(Date.now(), step, Date.now(), userId);
    const codes = replaceRecoveryCodes(userId);
    // Other sessions were established without the second factor — sign them out.
    revokeAllSessions(userId, 'mfa_enabled', currentSessionId);
    db.prepare('UPDATE sessions SET mfa_verified = 1 WHERE id = ?').run(currentSessionId);
    return codes;
  });
  audit(ctx, { action: 'auth.mfa_enabled', targetType: 'user', targetId: userId });
  return { recoveryCodes };
}

export async function disableMfa(userId: string, input: { password: string; code: string }, ctx: AuditContext): Promise<void> {
  const user = findUserById(userId);
  if (!user?.mfa_enabled_at) throw badRequest('Two-factor authentication is not enabled');
  await requirePasswordConfirmation(user, input.password, ctx, 'auth.mfa_disable_failed');
  if (!verifySecondFactor(user, input.code)) {
    audit(ctx, { action: 'auth.mfa_disable_failed', targetType: 'user', targetId: userId, success: false, metadata: { reason: 'bad_code' } });
    throw badRequest('Invalid authentication code');
  }
  tx(() => {
    db.prepare(`
      UPDATE users SET mfa_secret_enc = NULL, mfa_pending_secret_enc = NULL, mfa_enabled_at = NULL,
        mfa_last_used_step = NULL, updated_at = ? WHERE id = ?
    `).run(Date.now(), userId);
    db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(userId);
  });
  audit(ctx, { action: 'auth.mfa_disabled', targetType: 'user', targetId: userId });
  await mailer.send({ to: user.email, subject: 'Two-factor authentication disabled', text: 'Two-factor authentication was turned off for your account. If this wasn\'t you, reset your password immediately.' });
}

export async function regenerateRecoveryCodes(userId: string, password: string, ctx: AuditContext): Promise<{ recoveryCodes: string[] }> {
  const user = findUserById(userId);
  if (!user?.mfa_enabled_at) throw badRequest('Two-factor authentication is not enabled');
  await requirePasswordConfirmation(user, password, ctx, 'auth.recovery_codes_regenerate_failed');
  const recoveryCodes = tx(() => replaceRecoveryCodes(userId));
  audit(ctx, { action: 'auth.recovery_codes_regenerated', targetType: 'user', targetId: userId });
  return { recoveryCodes };
}

function replaceRecoveryCodes(userId: string): string[] {
  db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(userId);
  const insert = db.prepare('INSERT INTO mfa_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)');
  const codes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const raw = Array.from({ length: 10 }, () => RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)]).join('');
    insert.run(uuid(), userId, sha256(raw));
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}
