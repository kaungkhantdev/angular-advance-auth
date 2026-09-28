import type { NextFunction, Request, Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import { env } from '../config/env.ts';
import { AppError } from '../lib/errors.ts';
import type { AuditContext } from '../modules/audit/audit.service.ts';

export const CSRF_HEADER = 'x-csrf-protection';

/**
 * CSRF defence for the few endpoints authenticated by the refresh-token cookie
 * (refresh, logout). Layered on top of `SameSite=Strict`:
 *  1. A custom header must be present. Browsers cannot attach custom headers to a
 *     cross-site form post, and a cross-origin fetch with one triggers a CORS
 *     preflight that our origin allowlist rejects.
 *  2. If the browser sends an Origin header, it must be on the allowlist.
 */
export function requireCsrfHeader(req: Request, _res: Response, next: NextFunction): void {
  const origin = req.headers.origin;
  if (req.headers[CSRF_HEADER] !== '1' || (origin && !env.CORS_ORIGINS.includes(origin))) {
    throw new AppError(403, 'CSRF_REJECTED', 'Cross-site request rejected');
  }
  next();
}

const tooMany = (message: string) => (_req: Request, _res: Response, next: NextFunction) =>
  next(new AppError(429, 'RATE_LIMITED', message));

const skipInTests = () => env.NODE_ENV === 'test';

/** Coarse per-IP limit for the whole API. */
export const globalLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  skip: skipInTests,
  handler: tooMany('Too many requests, slow down'),
});

/**
 * Strict per-IP limit for credential endpoints (login, MFA, register, reset).
 * Complements per-account lockout: lockout stops targeted guessing on one account,
 * this stops one IP spraying many accounts.
 */
export const credentialLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  skip: skipInTests,
  handler: tooMany('Too many attempts, try again in a few minutes'),
});

export function clientContext(req: Request): AuditContext {
  return { actorId: req.auth?.userId ?? null, ip: req.ip ?? null, userAgent: req.get('user-agent') ?? null };
}
