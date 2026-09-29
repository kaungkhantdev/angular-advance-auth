/**
 * Permission catalog — the default definitions synced into the database at startup.
 *
 * Every resource exposes coarse `read` / `write` permissions plus optional
 * fine-grained actions. `write` *implies* the resource's mutating actions (and
 * `read`), so a role can be granted simple Read/Write access or tuned precisely.
 * Implications are stored in the DB and expanded server-side; clients receive
 * the catalog and each user's effective permissions from the API and never
 * hard-code them.
 *
 * Route handlers always check permissions, never role names, so roles can be
 * reshaped at runtime without touching code.
 */
interface ActionDef {
  description: string;
  /** Other permissions (full names) this one grants. Resolved transitively. */
  implies?: readonly string[];
}

interface ResourceDef {
  label: string;
  actions: Record<string, ActionDef>;
}

export const RESOURCES = {
  users: {
    label: 'Users',
    actions: {
      read: { description: 'View user accounts' },
      write: { description: 'Create, edit and delete user accounts', implies: ['users:read', 'users:create', 'users:update', 'users:delete'] },
      create: { description: 'Invite new users', implies: ['users:read'] },
      update: { description: 'Edit, lock/unlock and deactivate users', implies: ['users:read'] },
      delete: { description: 'Delete user accounts', implies: ['users:read'] },
      'assign-roles': { description: 'Grant or revoke roles on users', implies: ['users:read'] },
    },
  },
  roles: {
    label: 'Roles',
    actions: {
      read: { description: 'View roles and their permissions' },
      write: { description: 'Create, edit and delete custom roles', implies: ['roles:read', 'roles:create', 'roles:update', 'roles:delete'] },
      create: { description: 'Create custom roles', implies: ['roles:read'] },
      update: { description: 'Edit custom roles and their permissions', implies: ['roles:read'] },
      delete: { description: 'Delete custom roles', implies: ['roles:read'] },
    },
  },
  sessions: {
    label: 'Sessions',
    actions: {
      read: { description: "View any user's active sessions" },
      write: { description: "Sign out any user's sessions", implies: ['sessions:read', 'sessions:revoke'] },
      revoke: { description: "Sign out any user's sessions", implies: ['sessions:read'] },
    },
  },
  audit: {
    label: 'Audit log',
    actions: {
      read: { description: 'View the security audit log' },
    },
  },
  articles: {
    label: 'Articles',
    actions: {
      read: { description: 'Read published articles and own drafts' },
      write: {
        description: 'Create, edit and delete any article',
        implies: ['articles:read', 'articles:create', 'articles:update:any', 'articles:delete:any'],
      },
      'read-drafts': { description: 'Read unpublished drafts of any author', implies: ['articles:read'] },
      create: { description: 'Write articles', implies: ['articles:read'] },
      'update:own': { description: 'Edit own articles', implies: ['articles:read'] },
      'update:any': { description: 'Edit any article', implies: ['articles:update:own', 'articles:read-drafts'] },
      'delete:own': { description: 'Delete own articles', implies: ['articles:read'] },
      'delete:any': { description: 'Delete any article', implies: ['articles:delete:own', 'articles:read-drafts'] },
      publish: { description: 'Publish / unpublish articles', implies: ['articles:read-drafts'] },
    },
  },
} as const satisfies Record<string, ResourceDef>;

type Resources = typeof RESOURCES;
/** Compile-time union of every permission the code knows how to enforce. */
export type Permission = {
  [R in keyof Resources]: `${R & string}:${keyof Resources[R]['actions'] & string}`;
}[keyof Resources];

export interface PermissionDef {
  name: Permission;
  resource: string;
  action: string;
  description: string;
  implies: Permission[];
}

export const PERMISSION_DEFS: PermissionDef[] = Object.entries(RESOURCES).flatMap(([resource, def]) =>
  Object.entries(def.actions as Record<string, ActionDef>).map(([action, a]) => ({
    name: `${resource}:${action}` as Permission,
    resource,
    action,
    description: a.description,
    implies: (a.implies ?? []) as Permission[],
  })),
);

export const ALL_PERMISSIONS: Permission[] = PERMISSION_DEFS.map((p) => p.name);
const KNOWN = new Set<string>(ALL_PERMISSIONS);

export function isPermission(value: string): value is Permission {
  return KNOWN.has(value);
}

// Fail fast on typos in `implies` — a dangling implication would silently grant nothing.
for (const p of PERMISSION_DEFS) {
  for (const i of p.implies) if (!KNOWN.has(i)) throw new Error(`${p.name} implies unknown permission ${i}`);
}

export const SUPER_ADMIN_ROLE = 'super_admin';
export const DEFAULT_ROLE = 'user';

/**
 * System roles are created with these defaults on first boot and cannot be renamed or
 * deleted. Admins may edit their permissions afterwards, except super_admin, which is
 * always re-synced to every permission.
 */
export const SYSTEM_ROLES: Record<string, { description: string; permissions: readonly Permission[] }> = {
  [SUPER_ADMIN_ROLE]: {
    description: 'Unrestricted access. Can manage every role, including other super admins.',
    permissions: ALL_PERMISSIONS,
  },
  admin: {
    description: 'Manages users, sessions and content. Can view but not change role definitions.',
    permissions: [
      'users:write', 'users:assign-roles',
      'roles:read',
      'sessions:write',
      'audit:read',
      'articles:write', 'articles:publish',
    ],
  },
  editor: {
    description: 'Reviews, edits and publishes content from all authors.',
    permissions: ['articles:create', 'articles:update:any', 'articles:delete:own', 'articles:publish'],
  },
  [DEFAULT_ROLE]: {
    description: 'Default role for self-registered accounts.',
    permissions: ['articles:read', 'articles:create', 'articles:update:own', 'articles:delete:own'],
  },
};
