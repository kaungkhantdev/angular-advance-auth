import { HttpErrorResponse } from '@angular/common/http';
import type { ApiErrorBody } from '../auth/auth.models';

export function apiErrorCode(err: unknown): string | null {
  if (err instanceof HttpErrorResponse) return (err.error as ApiErrorBody | null)?.error?.code ?? null;
  return null;
}

/** Human-readable message for an API error, including field-level validation details. */
export function apiErrorMessage(err: unknown, fallback = 'Something went wrong. Please try again.'): string {
  if (!(err instanceof HttpErrorResponse)) return fallback;
  if (err.status === 0) return 'Cannot reach the server. Check your connection.';
  const body = err.error as ApiErrorBody | null;
  const details = body?.error?.details;
  if (Array.isArray(details) && details.length) return details.map((d) => d.message).join('. ');
  return body?.error?.message ?? fallback;
}
