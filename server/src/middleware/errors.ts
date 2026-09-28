import type { NextFunction, Request, Response } from 'express';
import { z, ZodError } from 'zod';
import { isProd } from '../config/env.ts';
import { AppError, badRequest } from '../lib/errors.ts';

/** Parses untrusted input; throws a 400 with field-level issues on failure. */
export function parse<S extends z.ZodType>(schema: S, data: unknown): z.infer<S> {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw badRequest('Validation failed', result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })));
  }
  return result.data;
}

export function notFoundHandler(_req: Request, _res: Response, next: NextFunction): void {
  next(new AppError(404, 'NOT_FOUND', 'Route not found'));
}

export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction): void {
  if (err instanceof AppError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message, details: err.details } });
    return;
  }
  if (err instanceof ZodError) {
    res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Validation failed', details: err.issues } });
    return;
  }
  // body-parser errors (malformed JSON, payload too large) carry a status.
  const status = (err as { status?: number })?.status;
  if (typeof status === 'number' && status >= 400 && status < 500) {
    res.status(status).json({ error: { code: 'BAD_REQUEST', message: 'Malformed request' } });
    return;
  }
  console.error(err);
  res.status(500).json({
    error: { code: 'INTERNAL', message: 'Something went wrong', ...(isProd ? {} : { details: String(err) }) },
  });
}
