import { argon2, createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { env } from '../config/env.ts';

const argon2Async = promisify(argon2);

/**
 * Argon2id with OWASP-recommended minimums (m=19 MiB, t=2, p=1).
 * Stored in PHC string format so parameters can be raised later and old
 * hashes re-hashed transparently on next login (see `needsRehash`).
 */
const ARGON2 = { memory: 19_456, passes: 2, parallelism: 1, tagLength: 32 } as const;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await argon2Async('argon2id', { message: password, nonce: salt, ...ARGON2 });
  return `$argon2id$v=19$m=${ARGON2.memory},t=${ARGON2.passes},p=${ARGON2.parallelism}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export async function verifyPassword(password: string, phc: string): Promise<boolean> {
  const match = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([\w-]+)\$([\w-]+)$/.exec(phc);
  if (!match) return false;
  const [, m, t, p, salt, expected] = match;
  const expectedBuf = Buffer.from(expected!, 'base64url');
  const actual = await argon2Async('argon2id', {
    message: password,
    nonce: Buffer.from(salt!, 'base64url'),
    memory: Number(m),
    passes: Number(t),
    parallelism: Number(p),
    tagLength: expectedBuf.length,
  });
  return timingSafeEqual(actual, expectedBuf);
}

export function needsRehash(phc: string): boolean {
  return !phc.startsWith(`$argon2id$v=19$m=${ARGON2.memory},t=${ARGON2.passes},p=${ARGON2.parallelism}$`);
}

/**
 * A valid hash of a random password. Verifying against it when the user does not
 * exist keeps login timing uniform, so response time does not reveal which
 * e-mail addresses are registered.
 */
export const DUMMY_PASSWORD_HASH = await hashPassword(randomBytes(16).toString('hex'));

/** High-entropy random tokens are hashed with plain SHA-256 — no need for a slow KDF. */
export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export const uuid = randomUUID;

// ---- Encryption at rest (AES-256-GCM) for secrets we must be able to read back (TOTP) ----

const dataKey = Buffer.from(env.DATA_ENCRYPTION_KEY, 'base64url');

export function encrypt(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}

export function decrypt(payload: string): string {
  const [version, iv, tag, ct] = payload.split('.');
  if (version !== 'v1' || !iv || !tag || !ct) throw new Error('Unsupported ciphertext format');
  const decipher = createDecipheriv('aes-256-gcm', dataKey, Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
}
