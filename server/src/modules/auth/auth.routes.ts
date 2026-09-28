import { Router, type CookieOptions, type Request, type Response } from 'express';
import { z } from 'zod';
import { isProd } from '../../config/env.ts';
import { authenticate, authOf } from '../../middleware/auth.ts';
import { parse } from '../../middleware/errors.ts';
import { clientContext, credentialLimiter, requireCsrfHeader } from '../../middleware/security.ts';
import { notFound } from '../../lib/errors.ts';
import { passwordSchema } from '../../lib/password-policy.ts';
import { audit } from '../audit/audit.service.ts';
import * as auth from './auth.service.ts';
import { listActiveSessions, revokeAllSessions, revokeUserSession, sessionIdFromRefreshToken } from './session.service.ts';

/**
 * The refresh token lives in an HttpOnly cookie (unreadable by JS → safe from XSS
 * exfiltration), scoped to /api/auth so it is never sent with ordinary API calls.
 * The short-lived access token is returned in the body and kept in memory only.
 */
export const REFRESH_COOKIE = isProd ? '__Secure-rt' : 'rt';
const cookieOptions: CookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: 'strict',
  path: '/api/auth',
};

function sendAuth(res: Response, result: auth.AuthResult): void {
  res.cookie(REFRESH_COOKIE, result.refreshToken, { ...cookieOptions, expires: new Date(result.refreshExpiresAt) });
  res.json({ accessToken: result.accessToken, expiresIn: result.expiresIn, user: result.user });
}

const clearRefreshCookie = (res: Response) => res.clearCookie(REFRESH_COOKIE, cookieOptions);
const client = (req: Request) => ({ ip: req.ip ?? null, userAgent: req.get('user-agent') ?? null });
const email = z.email().max(254).transform((e) => e.trim().toLowerCase());

export const authRouter = Router();

// ---- Public, credential endpoints (rate limited) ----

authRouter.post('/register', credentialLimiter, async (req, res) => {
  const body = parse(z.object({ email, name: z.string().trim().min(1).max(100), password: passwordSchema }), req.body);
  await auth.register(body, clientContext(req));
  // Identical response whether or not the e-mail was already registered.
  res.status(202).json({ message: 'Check your inbox to verify your e-mail address.' });
});

authRouter.post('/verify-email', credentialLimiter, (req, res) => {
  const { token } = parse(z.object({ token: z.string().min(1).max(200) }), req.body);
  auth.verifyEmail(token, clientContext(req));
  res.json({ message: 'E-mail verified. You can now sign in.' });
});

authRouter.post('/resend-verification', credentialLimiter, async (req, res) => {
  const body = parse(z.object({ email }), req.body);
  await auth.resendVerification(body.email);
  res.status(202).json({ message: 'If that account needs verification, a new link is on its way.' });
});

authRouter.post('/login', credentialLimiter, async (req, res) => {
  // No password policy on login — only bound the length to cap hashing cost.
  const body = parse(z.object({ email, password: z.string().min(1).max(128) }), req.body);
  const result = await auth.login(body, client(req));
  if (result.mfaRequired) {
    res.json({ mfaRequired: true, mfaToken: result.mfaToken });
    return;
  }
  sendAuth(res, result);
});

authRouter.post('/login/mfa', credentialLimiter, async (req, res) => {
  const body = parse(z.object({ mfaToken: z.string().min(1).max(2000), code: z.string().trim().min(6).max(20) }), req.body);
  sendAuth(res, await auth.completeMfaLogin(body, client(req)));
});

authRouter.post('/forgot-password', credentialLimiter, async (req, res) => {
  const body = parse(z.object({ email }), req.body);
  await auth.forgotPassword(body.email, clientContext(req));
  res.status(202).json({ message: 'If an account exists for that e-mail, a reset link has been sent.' });
});

authRouter.post('/reset-password', credentialLimiter, async (req, res) => {
  const body = parse(z.object({ token: z.string().min(1).max(200), password: passwordSchema }), req.body);
  await auth.resetPassword(body, clientContext(req));
  clearRefreshCookie(res);
  res.json({ message: 'Password updated. Please sign in with your new password.' });
});

// ---- Cookie-authenticated endpoints (CSRF protected) ----

authRouter.post('/refresh', requireCsrfHeader, async (req, res) => {
  try {
    sendAuth(res, await auth.refresh(req.cookies?.[REFRESH_COOKIE], client(req)));
  } catch (err) {
    // Keep the cookie on a benign race — a sibling request already holds the new one.
    if ((err as { code?: string }).code !== 'REFRESH_RACE') clearRefreshCookie(res);
    throw err;
  }
});

authRouter.post('/logout', requireCsrfHeader, (req, res) => {
  auth.logout(sessionIdFromRefreshToken(req.cookies?.[REFRESH_COOKIE]), clientContext(req));
  clearRefreshCookie(res);
  res.status(204).end();
});

// ---- Authenticated self-service ----

authRouter.use(authenticate);

authRouter.get('/me', (req, res) => {
  res.json(auth.currentUser(authOf(req).userId));
});

authRouter.post('/logout-all', (req, res) => {
  const { userId } = authOf(req);
  const count = revokeAllSessions(userId, 'logout_all');
  audit(clientContext(req), { action: 'auth.logout_all', targetType: 'user', targetId: userId, metadata: { count } });
  clearRefreshCookie(res);
  res.status(204).end();
});

authRouter.post('/change-password', credentialLimiter, async (req, res) => {
  const body = parse(z.object({ currentPassword: z.string().min(1).max(128), newPassword: passwordSchema }), req.body);
  const { userId, sessionId } = authOf(req);
  await auth.changePassword(userId, sessionId, body, clientContext(req));
  res.json({ message: 'Password changed. Other devices have been signed out.' });
});

authRouter.get('/sessions', (req, res) => {
  const { userId, sessionId } = authOf(req);
  res.json(listActiveSessions(userId, sessionId));
});

authRouter.delete('/sessions/:id', (req, res) => {
  const { userId } = authOf(req);
  const id = String(req.params.id);
  if (!revokeUserSession(userId, id, 'revoked_by_user')) throw notFound('Session');
  audit(clientContext(req), { action: 'auth.session_revoked', targetType: 'session', targetId: id });
  res.status(204).end();
});

// ---- MFA enrolment (password step-up required) ----

authRouter.post('/mfa/setup', credentialLimiter, async (req, res) => {
  const { password } = parse(z.object({ password: z.string().min(1).max(128) }), req.body);
  res.json(await auth.startMfaSetup(authOf(req).userId, password, clientContext(req)));
});

authRouter.post('/mfa/enable', credentialLimiter, (req, res) => {
  const { code } = parse(z.object({ code: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code') }), req.body);
  const { userId, sessionId } = authOf(req);
  res.json(auth.confirmMfaSetup(userId, sessionId, code, clientContext(req)));
});

authRouter.post('/mfa/disable', credentialLimiter, async (req, res) => {
  const body = parse(z.object({ password: z.string().min(1).max(128), code: z.string().trim().min(6).max(20) }), req.body);
  await auth.disableMfa(authOf(req).userId, body, clientContext(req));
  res.status(204).end();
});

authRouter.post('/mfa/recovery-codes', credentialLimiter, async (req, res) => {
  const { password } = parse(z.object({ password: z.string().min(1).max(128) }), req.body);
  res.json(await auth.regenerateRecoveryCodes(authOf(req).userId, password, clientContext(req)));
});
