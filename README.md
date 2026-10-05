# Advance Auth — Angular + Node authentication & RBAC

A production-style reference implementation of authentication and role-based
access control (RBAC):

- **`client/`** — Angular 22 SPA (standalone, zoneless, signals, `@Service()` DI)
- **`server/`** — Node 24.7+ / Express 5 API in TypeScript, run natively by Node.
  It has no native modules: password hashing uses Node's built-in `crypto.argon2`
  and storage uses `node:sqlite`.

## Quick start

```bash
npm run setup          # install both apps + create DB, super admin and demo users
npm run dev:api        # http://localhost:3000
npm run dev:web        # http://localhost:4200  (proxies /api → API)
```

Secrets live in `server/.env` (copy `server/.env.example`; generate each secret with the
command in the comments). Seeded accounts for local development:

| E-mail                    | Password                  | Role          |
|---------------------------|---------------------------|---------------|
| `superadmin@example.com`  | `SEED_ADMIN_PASSWORD` in `.env` | super_admin |
| `admin@example.com`       | `Demo!Password2026`       | admin         |
| `editor@example.com`      | `Demo!Password2026`       | editor        |
| `user@example.com`        | `Demo!Password2026`       | user          |

In development, e-mails (verification, password reset, invites, security alerts) are
printed to the API console.

Tests: `npm test` (32 API integration tests + client unit tests).

---

## Authentication

| Concern | Implementation |
|---|---|
| Password storage | Argon2id (OWASP params: m=19 MiB, t=2, p=1), PHC format, transparent re-hash on login when params change |
| Password policy | NIST 800-63B: ≥12 chars, ≤128, blocklist of common passwords, no name/e-mail inside, no composition rules |
| Access token | HS256 JWT, **15 min**, pinned algorithm, `iss`/`aud`/`typ` validated. Carries identity only (`sub`, `sid`), never roles |
| Refresh token | Opaque random token, **HttpOnly + SameSite=Strict + Secure (prod)** cookie scoped to `/api/auth`, stored server-side as SHA-256 |
| Rotation & theft detection | New refresh token on every use; replaying an old one **revokes the whole session**. A 15 s grace window turns benign multi-tab races into a retryable `REFRESH_RACE` |
| Session lifetime | 7-day sliding idle timeout + 30-day absolute cap |
| Instant revocation | Every request checks the session row, so logout, "sign out everywhere", password change and account disable take effect immediately |
| MFA | TOTP (RFC 6238), secrets **AES-256-GCM encrypted at rest**, replay protection (a code works once), 10 single-use recovery codes, password step-up to enrol, disable or regenerate codes |
| MFA challenge | Separate signing key and `typ`, 5-min expiry. It can never be used as an access token |
| Brute force | Per-account lockout (5 failures → 15 min, e-mail alert, MFA failures count too) **plus** per-IP rate limits on credential endpoints |
| Enumeration resistance | Same response and timing for unknown e-mail vs wrong password, registration of an existing e-mail, and forgot-password |
| E-mail flows | Verification required before first sign-in; single-use, hashed, expiring tokens (verify 24 h, reset 30 min, invite 72 h); password reset revokes all sessions |
| CSRF | Access token only accepted from the `Authorization` header. The cookie endpoints (`/refresh`, `/logout`) need a custom header and an allow-listed `Origin`, on top of SameSite=Strict |
| Hardening | Helmet headers, strict CORS allowlist, `Cache-Control: no-store`, 100 kB body limit, input validation with Zod everywhere, generic 500s, fail-fast config validation |

### SPA token handling

- The access token is kept **in memory only**, never in `localStorage` or `sessionStorage`.
- On page load, `provideAppInitializer` silently restores the session from the refresh cookie.
- The interceptor refreshes **once** for any number of concurrent 401s, then replays the requests.
- It refreshes proactively at 80 % of the token lifetime and syncs logout across tabs with `BroadcastChannel`.
- Tokens are only attached to same-origin `/api` calls. Post-login redirects are validated to prevent open redirects.
- One-time tokens are stripped from the address bar, and pages use `referrer: no-referrer`.

## Authorization (RBAC)

```
User ──< user_roles >── Role ──< role_permissions >── Permission (resource:action)
```

- **One permission per action.** Every resource (`users`, `roles`, `sessions`, `audit`,
  `articles`) has one permission per action (`articles:read`, `articles:update:own`,
  `articles:publish`, …). Permissions don't include each other: a role grants exactly the
  permissions it lists, and a user has every permission from all of their roles.
- **Server-defined, served dynamically.** Permissions are defined on the server
  (`server/src/rbac/permissions.ts`) and synced to the DB at startup. The client has **no
  hard-coded permission list**:
  - `/api/auth/me` returns the user's permissions;
  - `/api/roles/permissions` returns the catalog grouped by resource.

  The role editor renders its checklist entirely from that data.
- **Roles are data.** System roles (`super_admin`, `admin`, `editor`, `user`) are created
  with defaults on first boot. After that their permissions can be edited in the UI, but they
  can't be renamed or deleted. `super_admin` stays locked to every permission. Custom roles
  are built in the UI.
- **Check permissions, not role names.** Routes use `requirePermission('users:update')`
  (always the most specific action) and deny by default.
- **Resolved per request.** Role changes apply on the user's next request,
  with no stale JWT claims.
- **Resource-level policies.** RBAC is combined with ownership in pure policy functions
  (`article.policy.ts`): `articles:update:own` vs `articles:update:any`. Unreadable drafts
  return 404 rather than 403, so their existence isn't leaked. The API also returns per-item
  `can` flags so the UI never duplicates business rules.

**Anti-privilege-escalation rules** (all enforced server-side and tested):
1. You can only grant or revoke a role, or define a role, using permissions **you hold yourself**.
2. Only a super admin can grant or revoke `super_admin`.
3. You cannot change your own roles, status or account through admin endpoints.
4. You can only manage users whose permissions are a **subset of yours**, so an admin can't disable a super admin.
5. The last active super admin cannot be removed or disabled.
6. `super_admin` cannot be edited, and system roles cannot be renamed or deleted.

On the client, the `*hasPermission` directive, `requirePermissions()` guards and a
permission-filtered nav are **UX only**. The server is the only authority.

### Audit log

All security events go to an append-only `audit_logs` table (viewable with `audit:read`):
logins, failures, lockouts, token reuse, MFA changes, role grants, and user and article changes.
Secrets are never written to it.

## Database

See [docs/ERD.md](docs/ERD.md) for the entity-relationship diagram and table notes.

## Project layout

```
server/src
  config/env.ts            validated configuration (fails fast)
  db/                      node:sqlite connection, migrations, seed
  lib/                     crypto (argon2id, AES-GCM), TOTP, password policy, mailer
  middleware/              authenticate, requirePermission, CSRF, rate limits, errors
  rbac/                    permission catalog, principal loading, delegation rules
  modules/auth             login/MFA/refresh/reset/sessions  (routes + services)
  modules/users|roles      admin APIs with escalation guards
  modules/articles         example resource: RBAC + ownership policy
  modules/audit            audit trail
client/src/app
  core/auth                AuthService, interceptor, guards, *hasPermission
  core/api                 typed API clients
  features/                auth pages, dashboard, account security, articles, admin
```

## Going to production

- Serve SPA and API from the **same site** behind a reverse proxy (TLS), set `NODE_ENV=production`,
  `TRUST_PROXY`, `CORS_ORIGINS`, `APP_URL`, and fresh secrets from a secret manager.
- Add a strict **Content-Security-Policy** for the SPA (allow `img-src data:` for the QR code).
- Replace `ConsoleMailer` with a real provider (SES, Postmark, …).
- For multiple API instances, move rate-limit counters to a shared store (Redis) and consider
  Postgres instead of SQLite. The data layer is plain SQL, so porting is straightforward.
- Optional: check new passwords against Have I Been Pwned (k-anonymity), add WebAuthn/passkeys.
