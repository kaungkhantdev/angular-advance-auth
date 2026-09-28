import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Service } from '@angular/core';
import type { Permission } from '../auth/permissions';
import type { AdminUser, AuditEntry, Page, PermissionGroup, Role, Session } from './api.models';

const params = (obj: Record<string, string | number | undefined>) =>
  new HttpParams({ fromObject: Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== '')) as Record<string, string> });

@Service()
export class UsersApi {
  private readonly http = inject(HttpClient);
  private readonly base = '/api/users';

  list(q: { search?: string; limit?: number; offset?: number } = {}) {
    return this.http.get<Page<AdminUser>>(this.base, { params: params(q) });
  }
  get(id: string) {
    return this.http.get<AdminUser>(`${this.base}/${id}`);
  }
  create(body: { email: string; name: string; roleIds: string[] }) {
    return this.http.post<AdminUser>(this.base, body);
  }
  update(id: string, body: { name?: string; status?: 'active' | 'disabled' }) {
    return this.http.patch<AdminUser>(`${this.base}/${id}`, body);
  }
  unlock(id: string) {
    return this.http.post<AdminUser>(`${this.base}/${id}/unlock`, {});
  }
  delete(id: string) {
    return this.http.delete<void>(`${this.base}/${id}`);
  }
  setRoles(id: string, roleIds: string[]) {
    return this.http.put<AdminUser>(`${this.base}/${id}/roles`, { roleIds });
  }
  sessions(id: string) {
    return this.http.get<Session[]>(`${this.base}/${id}/sessions`);
  }
  revokeSessions(id: string) {
    return this.http.delete<{ revoked: number }>(`${this.base}/${id}/sessions`);
  }
}

@Service()
export class RolesApi {
  private readonly http = inject(HttpClient);
  private readonly base = '/api/roles';

  list() {
    return this.http.get<Role[]>(this.base);
  }
  get(id: string) {
    return this.http.get<Role>(`${this.base}/${id}`);
  }
  permissions() {
    return this.http.get<PermissionGroup[]>(`${this.base}/permissions`);
  }
  create(body: { name: string; description: string; permissions: Permission[] }) {
    return this.http.post<Role>(this.base, body);
  }
  update(id: string, body: { name?: string; description?: string; permissions?: Permission[] }) {
    return this.http.patch<Role>(`${this.base}/${id}`, body);
  }
  delete(id: string) {
    return this.http.delete<void>(`${this.base}/${id}`);
  }
}

@Service()
export class AuditApi {
  private readonly http = inject(HttpClient);

  list(q: { limit?: number; offset?: number; action?: string; actorId?: string } = {}) {
    return this.http.get<Page<AuditEntry>>('/api/audit', { params: params(q) });
  }
}
