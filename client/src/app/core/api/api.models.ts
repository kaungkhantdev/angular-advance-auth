import type { Permission } from '../auth/permissions';

export interface Page<T> {
  total: number;
  items: T[];
}

export interface AdminUser {
  id: string;
  email: string;
  name: string;
  status: 'active' | 'disabled';
  emailVerified: boolean;
  mfaEnabled: boolean;
  locked: boolean;
  lastLoginAt: number | null;
  createdAt: number;
  roles: string[];
}

export interface Role {
  id: string;
  name: string;
  description: string;
  isSystem: boolean;
  userCount: number;
  /** Directly assigned permissions. */
  permissions: Permission[];
  /** Everything the role grants, with implications (e.g. write ⇒ update) expanded by the server. */
  effectivePermissions: Permission[];
  createdAt: number;
  updatedAt: number;
}

export interface PermissionInfo {
  name: Permission;
  action: string;
  description: string;
  /** Permissions this one directly implies. */
  implies: Permission[];
  /** Everything this permission grants, transitively. */
  grants: Permission[];
}

/** Server-defined catalog, grouped by resource. */
export interface PermissionGroup {
  resource: string;
  label: string;
  permissions: PermissionInfo[];
}

export interface Session {
  id: string;
  ip: string | null;
  userAgent: string | null;
  mfaVerified: boolean;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  current: boolean;
}

export interface AuditEntry {
  id: number;
  at: number;
  actorId: string | null;
  actorEmail: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  success: boolean;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown> | null;
}

export interface Article {
  id: string;
  authorId: string;
  authorName: string;
  title: string;
  body: string;
  status: 'draft' | 'published';
  publishedAt: number | null;
  createdAt: number;
  updatedAt: number;
  /** Server-computed abilities for *this* article (RBAC + ownership). */
  can: { update: boolean; delete: boolean; publish: boolean };
}

export interface MfaSetup {
  secret: string;
  otpauthUrl: string;
  qrCodeDataUrl: string;
}

export interface Message {
  message: string;
}
