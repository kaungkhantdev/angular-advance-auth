/**
 * Bootstraps the RBAC catalog and the first super admin. Idempotent.
 * With `--demo`, also creates one verified user per system role for local testing.
 */
import { env } from '../config/env.ts';
import { hashPassword, uuid } from '../lib/crypto.ts';
import { SUPER_ADMIN_ROLE } from '../rbac/permissions.ts';
import { syncRbacCatalog } from '../rbac/rbac.service.ts';
import { db, tx } from './database.ts';

syncRbacCatalog();

async function ensureUser(email: string, name: string, password: string, role: string): Promise<boolean> {
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return false;
  const hash = await hashPassword(password);
  const now = Date.now();
  const id = uuid();
  tx(() => {
    db.prepare(`
      INSERT INTO users (id, email, name, password_hash, email_verified_at, password_changed_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, email, name, hash, now, now, now, now);
    db.prepare('INSERT INTO user_roles (user_id, role_id, granted_at) SELECT ?, id, ? FROM roles WHERE name = ?').run(id, now, role);
  });
  return true;
}

const hasSuperAdmin = db.prepare(
  'SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.name = ?',
).get(SUPER_ADMIN_ROLE);

if (!hasSuperAdmin) {
  if (!env.SEED_ADMIN_EMAIL || !env.SEED_ADMIN_PASSWORD || env.SEED_ADMIN_PASSWORD.length < 12) {
    console.error('Set SEED_ADMIN_EMAIL and SEED_ADMIN_PASSWORD (min 12 chars) to create the first super admin.');
    process.exit(1);
  }
  await ensureUser(env.SEED_ADMIN_EMAIL, 'Super Admin', env.SEED_ADMIN_PASSWORD, SUPER_ADMIN_ROLE);
  console.log(`Created super admin ${env.SEED_ADMIN_EMAIL}`);
} else {
  console.log('Super admin already exists — skipped.');
}

if (process.argv.includes('--demo')) {
  if (env.NODE_ENV === 'production') {
    console.error('Refusing to create demo accounts in production.');
    process.exit(1);
  }
  const demoPassword = 'Demo!Password2026';
  for (const role of ['admin', 'editor', 'user']) {
    if (await ensureUser(`${role}@example.com`, `Demo ${role}`, demoPassword, role)) {
      console.log(`Created ${role}@example.com / ${demoPassword}`);
    }
  }
}
