/**
 * Forward-only, append-only migrations. Never edit a migration that has shipped —
 * add a new one. All timestamps are epoch milliseconds (INTEGER).
 */
export const migrations: readonly string[] = [
  /* 001 — initial schema */ `
  CREATE TABLE users (
    id                     TEXT PRIMARY KEY,
    email                  TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name                   TEXT NOT NULL,
    password_hash          TEXT NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    email_verified_at      INTEGER,
    failed_login_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until           INTEGER,
    mfa_secret_enc         TEXT,
    mfa_pending_secret_enc TEXT,
    mfa_enabled_at         INTEGER,
    mfa_last_used_step     INTEGER,
    password_changed_at    INTEGER NOT NULL,
    last_login_at          INTEGER,
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL
  );

  CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
  );

  CREATE TABLE permissions (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL
  );

  CREATE TABLE role_permissions (
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL REFERENCES permissions(name) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission)
  );

  CREATE TABLE user_roles (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id)
  );
  CREATE INDEX idx_user_roles_role ON user_roles(role_id);

  -- One row per signed-in device. The refresh token is "<session id>.<secret>";
  -- only a SHA-256 of the secret is stored.
  CREATE TABLE sessions (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL,
    prev_token_hash     TEXT,
    rotated_at          INTEGER,
    ip                  TEXT,
    user_agent          TEXT,
    mfa_verified        INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    last_used_at        INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at          INTEGER,
    revoked_reason      TEXT
  );
  CREATE INDEX idx_sessions_user ON sessions(user_id);

  CREATE TABLE mfa_recovery_codes (
    id        TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   INTEGER
  );
  CREATE INDEX idx_recovery_user ON mfa_recovery_codes(user_id);

  -- Single-use, expiring tokens for e-mail verification and password reset.
  CREATE TABLE one_time_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX idx_ott_user_purpose ON one_time_tokens(user_id, purpose);

  -- Append-only security log. actor/target ids are not FKs so history survives deletes.
  CREATE TABLE audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    actor_id    TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    success     INTEGER NOT NULL DEFAULT 1,
    ip          TEXT,
    user_agent  TEXT,
    metadata    TEXT
  );
  CREATE INDEX idx_audit_at ON audit_logs(at DESC);
  CREATE INDEX idx_audit_actor ON audit_logs(actor_id);

  CREATE TABLE articles (
    id           TEXT PRIMARY KEY,
    author_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    body         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    published_at INTEGER,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
  );
  CREATE INDEX idx_articles_author ON articles(author_id);
  `,

  /* 002 — resource/action metadata and permission implications (e.g. write ⇒ create/update/delete) */ `
  ALTER TABLE permissions ADD COLUMN resource TEXT NOT NULL DEFAULT '';
  ALTER TABLE permissions ADD COLUMN action   TEXT NOT NULL DEFAULT '';

  CREATE TABLE permission_implications (
    permission TEXT NOT NULL REFERENCES permissions(name) ON DELETE CASCADE,
    implies    TEXT NOT NULL REFERENCES permissions(name) ON DELETE CASCADE,
    PRIMARY KEY (permission, implies)
  );
  `,

  /* 003 — drop permission implications: roles now list every permission explicitly.
     Each role first receives the permissions it used to get through implications, so
     nobody loses access. */ `
  WITH RECURSIVE eff(role_id, permission) AS (
    SELECT role_id, permission FROM role_permissions
    UNION
    SELECT eff.role_id, pi.implies FROM permission_implications pi JOIN eff ON pi.permission = eff.permission
  )
  INSERT OR IGNORE INTO role_permissions (role_id, permission) SELECT role_id, permission FROM eff;

  DROP TABLE permission_implications;
  `,

  /* 004 — surrogate key for permissions: permissions.id is the primary key and name stays
     UNIQUE (it is what code checks). role_permissions now references permission_id.
     SQLite can't change a primary key in place, so both tables are rebuilt. */ `
  ALTER TABLE permissions RENAME TO permissions_old;

  CREATE TABLE permissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    resource    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL
  );
  INSERT INTO permissions (name, resource, action, description)
    SELECT name, resource, action, description FROM permissions_old ORDER BY rowid;

  CREATE TABLE role_permissions_new (
    role_id       TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
  );
  INSERT INTO role_permissions_new (role_id, permission_id)
    SELECT rp.role_id, p.id FROM role_permissions rp JOIN permissions p ON p.name = rp.permission;

  DROP TABLE role_permissions;
  DROP TABLE permissions_old;
  ALTER TABLE role_permissions_new RENAME TO role_permissions;
  `,
];
