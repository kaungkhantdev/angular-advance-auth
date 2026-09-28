import type { NextFunction, Request, Response } from 'express';
import { forbidden, unauthorized } from '../lib/errors.ts';
import { verifyAccessToken } from '../modules/auth/token.service.ts';
import { isSessionActive } from '../modules/auth/session.service.ts';
import type { Permission } from '../rbac/permissions.ts';
import { hasPermission, loadPrincipal, type Principal } from '../rbac/rbac.service.ts';

export interface AuthContext {
  userId: string;
  sessionId: string;
  principal: Principal;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

/**
 * Authentication: verifies the Bearer access token, confirms the session has not
 * been revoked, and loads the caller's current roles/permissions.
 * Tokens are only accepted from the Authorization header — never from cookies or
 * query strings — which makes these endpoints immune to CSRF.
 */
export async function authenticate(req: Request, _res: Response, next: NextFunction): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) throw unauthorized();
  const claims = await verifyAccessToken(header.slice(7).trim());
  if (!isSessionActive(claims.sid, claims.sub)) throw unauthorized('Session has been revoked', 'SESSION_REVOKED');

  const principal = loadPrincipal(claims.sub);
  req.auth = { userId: claims.sub, sessionId: claims.sid, principal };
  next();
}

/**
 * Authorization: deny-by-default guard that requires ALL listed permissions.
 * Must run after `authenticate`.
 */
export function requirePermission(...permissions: Permission[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) throw unauthorized();
    if (!hasPermission(req.auth.principal, ...permissions)) throw forbidden();
    next();
  };
}

/** Requires at least one of the listed permissions (e.g. `:own` OR `:any`, refined by the handler). */
export function requireAnyPermission(...permissions: Permission[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) throw unauthorized();
    if (!permissions.some((p) => req.auth!.principal.permissions.has(p))) throw forbidden();
    next();
  };
}

/** Narrowing helper for handlers mounted behind `authenticate`. */
export function authOf(req: Request): AuthContext {
  if (!req.auth) throw unauthorized();
  return req.auth;
}
