// Test environment must be configured before any app module is loaded.
process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
process.env.JWT_ACCESS_SECRET = 'test-access-secret-0123456789-abcdefghij';
process.env.JWT_MFA_SECRET = 'test-mfa-secret-0123456789-abcdefghijklmn';
process.env.DATA_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64url');
process.env.CORS_ORIGINS = 'http://localhost:4200';

const { createApp } = await import('../src/app.ts');
const { db } = await import('../src/db/database.ts');
const { hashPassword, uuid } = await import('../src/lib/crypto.ts');
const { mailer } = await import('../src/lib/mailer.ts');
const request = (await import('supertest')).default;

export const app = createApp();
export { db, mailer, request };

export const PASSWORD = 'Correct-Horse-Battery-9';

export async function createUser(email: string, roles: string[] = ['user'], opts: { verified?: boolean } = {}) {
  const id = uuid();
  const now = Date.now();
  db.prepare(`
    INSERT INTO users (id, email, name, password_hash, email_verified_at, password_changed_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, email, email.split('@')[0]!, await hashPassword(PASSWORD), opts.verified === false ? null : now, now, now, now);
  for (const r of roles) {
    db.prepare('INSERT INTO user_roles (user_id, role_id, granted_at) SELECT ?, id, ? FROM roles WHERE name = ?').run(id, now, r);
  }
  return id;
}

export function roleId(name: string): string {
  return (db.prepare('SELECT id FROM roles WHERE name = ?').get(name) as { id: string }).id;
}

export function refreshCookie(res: { headers: Record<string, unknown> }): string {
  const cookies = (res.headers['set-cookie'] as string[] | undefined) ?? [];
  const c = cookies.find((x) => x.startsWith('rt=') && !x.startsWith('rt=;'));
  if (!c) throw new Error('no refresh cookie in response');
  return c.split(';')[0]!;
}

export async function login(email: string, password = PASSWORD) {
  const res = await request(app).post('/api/auth/login').send({ email, password });
  if (res.status !== 200 || !res.body.accessToken) throw new Error(`login failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { token: res.body.accessToken as string, cookie: refreshCookie(res), user: res.body.user };
}

export const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });
export const csrf = { 'X-CSRF-Protection': '1' };

export function lastMailTo(email: string) {
  const mail = [...mailer.outbox].reverse().find((m) => m.to === email);
  if (!mail) throw new Error(`no mail to ${email}`);
  return mail;
}

export function tokenFromMail(text: string): string {
  const m = /token=([\w-]+)/.exec(text);
  if (!m) throw new Error('no token in mail');
  return m[1]!;
}
