import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  app, bearer, createUser, csrf, db, lastMailTo, login, PASSWORD, refreshCookie, request, tokenFromMail,
} from './helpers.ts';
import { totpAt } from '../src/lib/totp.ts';

describe('registration & e-mail verification', () => {
  it('requires e-mail verification before sign-in', async () => {
    const email = 'new.person@example.com';
    const reg = await request(app).post('/api/auth/register').send({ email, name: 'New Person', password: PASSWORD });
    assert.equal(reg.status, 202);

    const early = await request(app).post('/api/auth/login').send({ email, password: PASSWORD });
    assert.equal(early.status, 403);
    assert.equal(early.body.error.code, 'EMAIL_NOT_VERIFIED');

    const token = tokenFromMail(lastMailTo(email).text);
    assert.equal((await request(app).post('/api/auth/verify-email').send({ token })).status, 200);
    assert.equal((await request(app).post('/api/auth/verify-email').send({ token })).status, 400, 'token is single-use');

    const { token: access } = await login(email);
    const me = await request(app).get('/api/auth/me').set(bearer(access));
    assert.deepEqual(me.body.roles, ['user']);
    assert.ok(me.body.permissions.includes('articles:create'));
    assert.ok(!me.body.permissions.includes('users:read'));
  });

  it('does not reveal whether an e-mail is already registered', async () => {
    await createUser('taken@example.com');
    const res = await request(app).post('/api/auth/register').send({ email: 'taken@example.com', name: 'X', password: PASSWORD });
    assert.equal(res.status, 202);
    assert.match(lastMailTo('taken@example.com').subject, /Sign-up attempt/);
  });

  it('enforces the password policy', async () => {
    const short = await request(app).post('/api/auth/register').send({ email: 'p1@example.com', name: 'P', password: 'short' });
    assert.equal(short.status, 400);
    const common = await request(app).post('/api/auth/register').send({ email: 'p2@example.com', name: 'P', password: 'password1234' });
    assert.equal(common.status, 400);
    const identity = await request(app).post('/api/auth/register').send({ email: 'jonathan@example.com', name: 'J', password: 'jonathan-rocks-2026' });
    assert.equal(identity.status, 400);
  });
});

describe('login', () => {
  it('returns the same error for unknown e-mail and wrong password', async () => {
    await createUser('login1@example.com');
    const a = await request(app).post('/api/auth/login').send({ email: 'nobody@example.com', password: PASSWORD });
    const b = await request(app).post('/api/auth/login').send({ email: 'login1@example.com', password: 'wrong-password-123' });
    assert.equal(a.status, 401);
    assert.deepEqual(a.body, b.body);
  });

  it('locks the account after 5 failed attempts, even for the right password', async () => {
    await createUser('lock@example.com');
    for (let i = 0; i < 5; i++) {
      await request(app).post('/api/auth/login').send({ email: 'lock@example.com', password: 'wrong-password-123' });
    }
    const res = await request(app).post('/api/auth/login').send({ email: 'lock@example.com', password: PASSWORD });
    assert.equal(res.status, 423);
    assert.match(lastMailTo('lock@example.com').subject, /locked/);
  });

  it('sets the refresh token as an HttpOnly, SameSite=Strict cookie scoped to /api/auth', async () => {
    await createUser('cookie@example.com');
    const res = await request(app).post('/api/auth/login').send({ email: 'cookie@example.com', password: PASSWORD });
    const raw = (res.headers['set-cookie'] as unknown as string[])[0]!;
    assert.match(raw, /HttpOnly/);
    assert.match(raw, /SameSite=Strict/);
    assert.match(raw, /Path=\/api\/auth/);
    assert.equal(res.body.refreshToken, undefined, 'refresh token must not be exposed to JS');
  });
});

describe('refresh token rotation', () => {
  it('rotates on every refresh and revokes the session when an old token is replayed', async () => {
    await createUser('rotate@example.com');
    const { cookie: first } = await login('rotate@example.com');

    const r1 = await request(app).post('/api/auth/refresh').set(csrf).set('Cookie', first);
    assert.equal(r1.status, 200);
    const second = refreshCookie(r1);
    assert.notEqual(first, second);

    // Simulate the grace window having passed, then replay the stolen first token.
    db.prepare('UPDATE sessions SET rotated_at = rotated_at - 60000').run();
    const replay = await request(app).post('/api/auth/refresh').set(csrf).set('Cookie', first);
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error.code, 'REFRESH_REUSE');

    // The legitimate holder is signed out too — the whole session is burned.
    const legit = await request(app).post('/api/auth/refresh').set(csrf).set('Cookie', second);
    assert.equal(legit.status, 401);
  });

  it('treats a concurrent refresh as a retryable race, not theft', async () => {
    await createUser('race@example.com');
    const { cookie } = await login('race@example.com');
    const r1 = await request(app).post('/api/auth/refresh').set(csrf).set('Cookie', cookie);
    const r2 = await request(app).post('/api/auth/refresh').set(csrf).set('Cookie', cookie);
    assert.equal(r2.status, 401);
    assert.equal(r2.body.error.code, 'REFRESH_RACE');
    assert.equal((await request(app).post('/api/auth/refresh').set(csrf).set('Cookie', refreshCookie(r1))).status, 200);
  });

  it('rejects refresh without the CSRF header or from a foreign origin', async () => {
    await createUser('csrf@example.com');
    const { cookie } = await login('csrf@example.com');
    assert.equal((await request(app).post('/api/auth/refresh').set('Cookie', cookie)).status, 403);
    const foreign = await request(app).post('/api/auth/refresh').set(csrf).set('Origin', 'https://evil.example').set('Cookie', cookie);
    assert.equal(foreign.status, 403);
  });
});

describe('logout & session management', () => {
  it('invalidates the access token immediately on logout', async () => {
    await createUser('logout@example.com');
    const { token, cookie } = await login('logout@example.com');
    assert.equal((await request(app).get('/api/auth/me').set(bearer(token))).status, 200);
    assert.equal((await request(app).post('/api/auth/logout').set(csrf).set('Cookie', cookie)).status, 204);
    const after = await request(app).get('/api/auth/me').set(bearer(token));
    assert.equal(after.status, 401);
    assert.equal(after.body.error.code, 'SESSION_REVOKED');
  });

  it('lets a user list and revoke their other sessions', async () => {
    await createUser('devices@example.com');
    const laptop = await login('devices@example.com');
    const phone = await login('devices@example.com');
    const list = await request(app).get('/api/auth/sessions').set(bearer(laptop.token));
    assert.equal(list.body.length, 2);
    const other = list.body.find((s: { current: boolean }) => !s.current);
    assert.equal((await request(app).delete(`/api/auth/sessions/${other.id}`).set(bearer(laptop.token))).status, 204);
    assert.equal((await request(app).get('/api/auth/me').set(bearer(phone.token))).status, 401);
  });

  it('rejects tampered and wrongly-signed tokens', async () => {
    await createUser('tamper@example.com');
    const { token } = await login('tamper@example.com');
    const [h, p] = token.split('.');
    assert.equal((await request(app).get('/api/auth/me').set(bearer(`${h}.${p}.invalidsig`))).status, 401);
    const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${p}.`;
    assert.equal((await request(app).get('/api/auth/me').set(bearer(none))).status, 401);
  });
});

describe('password reset & change', () => {
  it('resets via single-use e-mail link and signs out every device', async () => {
    await createUser('forgot@example.com');
    const { token: oldAccess } = await login('forgot@example.com');

    const unknown = await request(app).post('/api/auth/forgot-password').send({ email: 'ghost@example.com' });
    const known = await request(app).post('/api/auth/forgot-password').send({ email: 'forgot@example.com' });
    assert.equal(unknown.status, 202);
    assert.deepEqual(unknown.body, known.body);

    const resetToken = tokenFromMail(lastMailTo('forgot@example.com').text);
    const newPassword = 'Brand-New-Secret-2026';
    assert.equal((await request(app).post('/api/auth/reset-password').send({ token: resetToken, password: newPassword })).status, 200);
    assert.equal((await request(app).post('/api/auth/reset-password').send({ token: resetToken, password: newPassword })).status, 400);

    assert.equal((await request(app).get('/api/auth/me').set(bearer(oldAccess))).status, 401);
    await login('forgot@example.com', newPassword);
  });

  it('changing password keeps the current session but revokes others', async () => {
    await createUser('change@example.com');
    const a = await login('change@example.com');
    const b = await login('change@example.com');
    const res = await request(app).post('/api/auth/change-password').set(bearer(a.token))
      .send({ currentPassword: PASSWORD, newPassword: 'Another-Strong-Pass-77' });
    assert.equal(res.status, 200);
    assert.equal((await request(app).get('/api/auth/me').set(bearer(a.token))).status, 200);
    assert.equal((await request(app).get('/api/auth/me').set(bearer(b.token))).status, 401);
  });
});

describe('multi-factor authentication (TOTP)', () => {
  it('enrols, challenges on login, blocks code replay and accepts recovery codes once', async () => {
    await createUser('mfa@example.com');
    const { token } = await login('mfa@example.com');

    const setup = await request(app).post('/api/auth/mfa/setup').set(bearer(token)).send({ password: PASSWORD });
    assert.equal(setup.status, 200);
    assert.match(setup.body.otpauthUrl, /^otpauth:\/\/totp\//);
    const secret: string = setup.body.secret;
    const stored = db.prepare('SELECT mfa_pending_secret_enc FROM users WHERE email = ?').get('mfa@example.com') as { mfa_pending_secret_enc: string };
    assert.ok(!stored.mfa_pending_secret_enc.includes(secret), 'secret must be encrypted at rest');

    const code = totpAt(secret);
    const enable = await request(app).post('/api/auth/mfa/enable').set(bearer(token)).send({ code });
    assert.equal(enable.status, 200);
    assert.equal(enable.body.recoveryCodes.length, 10);

    const step1 = await request(app).post('/api/auth/login').send({ email: 'mfa@example.com', password: PASSWORD });
    assert.equal(step1.body.mfaRequired, true);
    assert.equal(step1.body.accessToken, undefined);
    assert.equal(step1.headers['set-cookie'], undefined);

    // The MFA challenge token is not an access token.
    assert.equal((await request(app).get('/api/auth/me').set(bearer(step1.body.mfaToken))).status, 401);

    const replay = await request(app).post('/api/auth/login/mfa').send({ mfaToken: step1.body.mfaToken, code });
    assert.equal(replay.status, 401, 'a TOTP code must not be accepted twice');

    const next = totpAt(secret, Date.now() + 30_000);
    const ok = await request(app).post('/api/auth/login/mfa').send({ mfaToken: step1.body.mfaToken, code: next });
    assert.equal(ok.status, 200);
    assert.ok(ok.body.accessToken);

    const recovery = enable.body.recoveryCodes[0];
    const viaRecovery = await request(app).post('/api/auth/login/mfa').send({ mfaToken: step1.body.mfaToken, code: recovery });
    assert.equal(viaRecovery.status, 200);
    const again = await request(app).post('/api/auth/login/mfa').send({ mfaToken: step1.body.mfaToken, code: recovery });
    assert.equal(again.status, 401, 'recovery codes are single-use');
  });
});
