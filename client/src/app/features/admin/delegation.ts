import type { Role } from '../../core/api/api.models';
import type { AuthService } from '../../core/auth/auth.service';

/**
 * UX mirror of the server's anti-escalation rule: you can only grant or revoke
 * roles whose permissions you hold yourself; super_admin only by a super admin.
 */
export function canDelegate(auth: AuthService, role: Role): boolean {
  const roles = auth.user()?.roles ?? [];
  if (role.name === 'super_admin' && !roles.includes('super_admin')) return false;
  return auth.hasPermission(...role.permissions);
}
