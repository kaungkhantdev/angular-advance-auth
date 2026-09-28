import { errors, jwtVerify, SignJWT } from 'jose';
import { env } from '../../config/env.ts';
import { uuid } from '../../lib/crypto.ts';
import { unauthorized } from '../../lib/errors.ts';

const accessKey = new TextEncoder().encode(env.JWT_ACCESS_SECRET);
const mfaKey = new TextEncoder().encode(env.JWT_MFA_SECRET);
const MFA_CHALLENGE_TTL = '5m';

export interface AccessClaims {
  sub: string;
  sid: string;
}

/**
 * Short-lived, stateless access token. It carries identity only (user + session),
 * never roles/permissions — those are resolved per request so they can't go stale.
 */
export async function signAccessToken(userId: string, sessionId: string): Promise<{ token: string; expiresIn: number }> {
  const token = await new SignJWT({ sid: sessionId })
    .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
    .setSubject(userId)
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setJti(uuid())
    .setIssuedAt()
    .setExpirationTime(`${env.ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(accessKey);
  return { token, expiresIn: env.ACCESS_TOKEN_TTL_SECONDS };
}

export async function verifyAccessToken(token: string): Promise<AccessClaims> {
  try {
    const { payload } = await jwtVerify(token, accessKey, {
      algorithms: ['HS256'], // pin the algorithm — never trust the token header's choice
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      typ: 'at+jwt',
    });
    if (typeof payload.sub !== 'string' || typeof payload.sid !== 'string') throw unauthorized('Invalid token');
    return { sub: payload.sub, sid: payload.sid };
  } catch (err) {
    if (err instanceof errors.JWTExpired) throw unauthorized('Access token expired', 'TOKEN_EXPIRED');
    throw unauthorized('Invalid access token', 'INVALID_TOKEN');
  }
}

/**
 * Proves the password step succeeded while the second factor is still pending.
 * Signed with a different key and `typ`, so it can never be used as an access token.
 */
export async function signMfaChallenge(userId: string): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'HS256', typ: 'mfa-challenge+jwt' })
    .setSubject(userId)
    .setIssuer(env.JWT_ISSUER)
    .setAudience(`${env.JWT_AUDIENCE}:mfa`)
    .setIssuedAt()
    .setExpirationTime(MFA_CHALLENGE_TTL)
    .sign(mfaKey);
}

export async function verifyMfaChallenge(token: string): Promise<string> {
  try {
    const { payload } = await jwtVerify(token, mfaKey, {
      algorithms: ['HS256'],
      issuer: env.JWT_ISSUER,
      audience: `${env.JWT_AUDIENCE}:mfa`,
      typ: 'mfa-challenge+jwt',
    });
    if (typeof payload.sub !== 'string') throw new Error('missing sub');
    return payload.sub;
  } catch {
    throw unauthorized('MFA challenge expired or invalid — sign in again', 'MFA_CHALLENGE_INVALID');
  }
}
