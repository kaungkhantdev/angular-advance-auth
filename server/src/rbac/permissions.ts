/**
 * Permission catalog — the definitions synced into the database at startup.
 *
 * Each permission is one action on one resource (`articles:publish`). Permissions
 * don't include each other: a role grants exactly the permissions it lists.
 * Clients receive the catalog and each user's permissions from the API and never
 * hard-code them.
 *
 * Route handlers always check permissions, never role names, so roles can be
 * reshaped at runtime without touching code.
 */
interface ActionDef {
  description: string;
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
      create: { description: 'Invite new users' },
      update: { description: 'Edit, lock/unlock and deactivate users' },
      delete: { description: 'Delete user accounts' },
      'assign-roles': { description: 'Grant or revoke roles on users' },
    },
  },
  roles: {
    label: 'Roles',
    actions: {
      read: { description: 'View roles and their permissions' },
      create: { description: 'Create custom roles' },
      update: { description: 'Edit roles and their permissions' },
      delete: { description: 'Delete custom roles' },
    },
  },
  sessions: {
    label: 'Sessions',
    actions: {
      read: { description: "View any user's active sessions" },
      revoke: { description: "Sign out any user's sessions" },
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
      'read-drafts': { description: 'Read unpublished drafts of any author' },
      create: { description: 'Write articles' },
      'update:own': { description: 'Edit own articles' },
      'update:any': { description: 'Edit any article' },
      'delete:own': { description: 'Delete own articles' },
      'delete:any': { description: 'Delete any article' },
      publish: { description: 'Publish / unpublish articles' },
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
}

export const PERMISSION_DEFS: PermissionDef[] = Object.entries(RESOURCES).flatMap(([resource, def]) =>
  Object.entries(def.actions as Record<string, ActionDef>).map(([action, a]) => ({
    name: `${resource}:${action}` as Permission,
    resource,
    action,
    description: a.description,
  })),
);

export const ALL_PERMISSIONS: Permission[] = PERMISSION_DEFS.map((p) => p.name);
const KNOWN = new Set<string>(ALL_PERMISSIONS);

export function isPermission(value: string): value is Permission {
  return KNOWN.has(value);
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
      'users:read', 'users:create', 'users:update', 'users:delete', 'users:assign-roles',
      'roles:read',
      'sessions:read', 'sessions:revoke',
      'audit:read',
      'articles:read', 'articles:read-drafts', 'articles:create', 'articles:update:own', 'articles:update:any',
      'articles:delete:own', 'articles:delete:any', 'articles:publish',
    ],
  },
  editor: {
    description: 'Reviews, edits and publishes content from all authors.',
    permissions: [
      'articles:read', 'articles:read-drafts', 'articles:create', 'articles:update:own', 'articles:update:any',
      'articles:delete:own', 'articles:publish',
    ],
  },
  [DEFAULT_ROLE]: {
    description: 'Default role for self-registered accounts.',
    permissions: ['articles:read', 'articles:create', 'articles:update:own', 'articles:delete:own'],
  },
};
