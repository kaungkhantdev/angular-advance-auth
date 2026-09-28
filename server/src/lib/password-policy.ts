import { z } from 'zod';

/**
 * NIST SP 800-63B aligned: favour length over composition rules, cap length to
 * bound hashing cost, and block known-breached / context-specific passwords.
 * In production, also consider a k-anonymity check against Have I Been Pwned.
 */
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;

const COMMON = new Set([
  'password1234', 'password12345', 'password123!', 'qwertyuiop12', 'qwerty123456', '123456789012',
  'iloveyou1234', 'administrator', 'letmein12345', 'welcome12345', 'changeme1234', 'passw0rd1234',
  'aaaaaaaaaaaa', '111111111111', 'abc123456789', 'football1234', 'monkey123456', 'superman1234',
]);

export const passwordSchema = z
  .string()
  .min(PASSWORD_MIN, `Password must be at least ${PASSWORD_MIN} characters`)
  .max(PASSWORD_MAX, `Password must be at most ${PASSWORD_MAX} characters`)
  .refine((p) => !COMMON.has(p.toLowerCase()), 'This password is too common')
  .refine((p) => new Set(p).size >= 5, 'Password is too repetitive');

/** Context check that needs other fields (e.g. e-mail) — call after schema validation. */
export function passwordContainsIdentity(password: string, email: string, name?: string): boolean {
  const lower = password.toLowerCase();
  const local = email.split('@')[0]!.toLowerCase();
  if (local.length >= 4 && lower.includes(local)) return true;
  return !!name && name.length >= 4 && lower.includes(name.toLowerCase());
}
