import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, OnInit, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import type { Observable } from 'rxjs';
import { RolesApi, UsersApi } from '../../core/api/admin.api';
import type { AdminUser, Role, Session } from '../../core/api/api.models';
import { AuthService } from '../../core/auth/auth.service';
import { HasPermissionDirective } from '../../core/auth/has-permission.directive';
import { apiErrorMessage } from '../../core/http/errors';
import { canDelegate } from './delegation';

@Component({
  selector: 'app-user-detail',
  imports: [RouterLink, DatePipe, HasPermissionDirective],
  template: `
    <p><a routerLink="/admin/users" class="small">← All users</a></p>
    @if (error()) { <div class="alert alert-error" role="alert">{{ error() }}</div> }
    @if (notice()) { <div class="alert alert-success">{{ notice() }}</div> }

    @if (user(); as u) {
      <div class="page-header spread">
        <div>
          <h1>{{ u.name }}</h1>
          <p class="muted">{{ u.email }} · joined {{ u.createdAt | date: 'mediumDate' }}</p>
        </div>
        <div class="row">
          @if (u.status === 'disabled') { <span class="badge badge-danger">Disabled</span> }
          @else if (u.locked) { <span class="badge badge-warning">Locked</span> }
          @else { <span class="badge badge-success">Active</span> }
          <span class="badge">{{ u.emailVerified ? 'E-mail verified' : 'Unverified' }}</span>
          <span class="badge">{{ u.mfaEnabled ? '2FA on' : '2FA off' }}</span>
        </div>
      </div>

      @if (isSelf()) {
        <div class="alert alert-info" style="margin-bottom: 1rem">
          This is your own account. To prevent self-escalation and accidental lock-out, another administrator must change your roles or status.
        </div>
      } @else if (!manageable()) {
        <div class="alert alert-info" style="margin-bottom: 1rem">
          This user holds permissions you don't have, so only a more privileged administrator can manage them.
        </div>
      }

      <div class="stack">
        <section class="card" *hasPermission="'users:assign-roles'">
          <h2>Roles</h2>
          <p class="small muted">Only roles whose permissions you hold can be granted or revoked.</p>
          <div class="stack-sm">
            @for (r of roles(); track r.id) {
              <label class="checkbox" [class.disabled]="!canToggle(r)">
                <input type="checkbox" [checked]="selected().has(r.id)" [disabled]="!canToggle(r)" (change)="toggle(r.id)" />
                <span><strong>{{ r.name }}</strong> <span class="small muted">— {{ r.description }}</span></span>
              </label>
            }
          </div>
          <div class="row" style="margin-top: 1rem">
            <button class="btn btn-primary" [disabled]="!rolesDirty() || busy() || readOnly()" (click)="saveRoles()">Save roles</button>
          </div>
        </section>

        <section class="card" *hasPermission="['users:update', 'users:delete']; mode: 'any'">
          <h2>Account actions</h2>
          <div class="row">
            <ng-container *hasPermission="'users:update'">
              @if (u.locked) { <button class="btn" (click)="unlock()" [disabled]="busy() || readOnly()">Unlock</button> }
              @if (u.status === 'active') {
                <button class="btn btn-danger" (click)="setStatus('disabled')" [disabled]="busy() || readOnly()">Disable account</button>
              } @else {
                <button class="btn" (click)="setStatus('active')" [disabled]="busy() || readOnly()">Re-enable account</button>
              }
            </ng-container>
            <button *hasPermission="'users:delete'" class="btn btn-danger" (click)="remove()" [disabled]="busy() || readOnly()">Delete user</button>
          </div>
          <p class="small muted" style="margin: .75rem 0 0">Disabling signs the user out of every device immediately.</p>
        </section>

        <section class="card" *hasPermission="'sessions:read'">
          <div class="spread">
            <h2>Active sessions <span class="badge">{{ sessions().length }}</span></h2>
            <button *hasPermission="'sessions:revoke'" class="btn btn-sm btn-danger" [disabled]="!sessions().length" (click)="revokeSessions()">Sign out all</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>IP</th><th>Device</th><th>Last active</th></tr></thead>
              <tbody>
                @for (s of sessions(); track s.id) {
                  <tr><td class="mono">{{ s.ip ?? '—' }}</td><td class="small">{{ s.userAgent ?? '—' }}</td><td>{{ s.lastUsedAt | date: 'short' }}</td></tr>
                } @empty { <tr><td colspan="3" class="muted">No active sessions.</td></tr> }
              </tbody>
            </table>
          </div>
        </section>
      </div>
    }
  `,
  styles: `.checkbox.disabled { opacity: .55; cursor: not-allowed; }`,
})
export class UserDetail implements OnInit {
  readonly id = input.required<string>();

  private readonly usersApi = inject(UsersApi);
  private readonly rolesApi = inject(RolesApi);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly user = signal<AdminUser | null>(null);
  protected readonly roles = signal<Role[]>([]);
  protected readonly sessions = signal<Session[]>([]);
  protected readonly selected = signal(new Set<string>());
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);

  protected readonly isSelf = computed(() => this.user()?.id === this.auth.user()?.id);
  /** UX mirror of the server's hierarchy rule: only manage users whose permissions ⊆ yours. */
  protected readonly manageable = computed(() => {
    if (this.auth.user()?.roles.includes('super_admin')) return true;
    const targetRoles = new Set(this.user()?.roles ?? []);
    return this.roles().filter((r) => targetRoles.has(r.name)).every((r) => this.auth.hasPermission(...r.permissions));
  });
  protected readonly readOnly = computed(() => this.isSelf() || !this.manageable());
  protected readonly rolesDirty = computed(() => {
    const current = new Set(this.roles().filter((r) => this.user()?.roles.includes(r.name)).map((r) => r.id));
    const sel = this.selected();
    return current.size !== sel.size || [...sel].some((id) => !current.has(id));
  });

  ngOnInit(): void {
    this.usersApi.get(this.id()).subscribe({
      next: (u) => { this.user.set(u); this.syncSelection(); },
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
    if (this.auth.hasPermission('roles:read')) {
      this.rolesApi.list().subscribe((r) => { this.roles.set(r); this.syncSelection(); });
    }
    if (this.auth.hasPermission('sessions:read')) this.loadSessions();
  }

  protected canToggle(role: Role): boolean {
    return !this.readOnly() && canDelegate(this.auth, role);
  }

  protected toggle(roleId: string): void {
    this.selected.update((s) => {
      const next = new Set(s);
      if (!next.delete(roleId)) next.add(roleId);
      return next;
    });
  }

  protected saveRoles(): void {
    this.act(this.usersApi.setRoles(this.id(), [...this.selected()]), (u) => {
      this.user.set(u);
      this.syncSelection();
      this.notice.set('Roles updated. The change applies to the user’s next request — no re-login needed.');
    });
  }

  protected setStatus(status: 'active' | 'disabled'): void {
    if (status === 'disabled' && !confirm('Disable this account and sign it out everywhere?')) return;
    this.act(this.usersApi.update(this.id(), { status }), (u) => {
      this.user.set(u);
      this.notice.set(status === 'disabled' ? 'Account disabled and signed out.' : 'Account re-enabled.');
      this.loadSessions();
    });
  }

  protected unlock(): void {
    this.act(this.usersApi.unlock(this.id()), (u) => { this.user.set(u); this.notice.set('Account unlocked.'); });
  }

  protected remove(): void {
    if (!confirm(`Permanently delete ${this.user()?.email}? This cannot be undone.`)) return;
    this.act(this.usersApi.delete(this.id()), () => void this.router.navigate(['/admin/users']));
  }

  protected revokeSessions(): void {
    this.act(this.usersApi.revokeSessions(this.id()), (r) => {
      this.notice.set(`Signed out ${r.revoked} session(s).`);
      this.sessions.set([]);
    });
  }

  private syncSelection(): void {
    const names = new Set(this.user()?.roles ?? []);
    this.selected.set(new Set(this.roles().filter((r) => names.has(r.name)).map((r) => r.id)));
  }

  private loadSessions(): void {
    if (!this.auth.hasPermission('sessions:read')) return;
    this.usersApi.sessions(this.id()).subscribe({ next: (s) => this.sessions.set(s) });
  }

  private act<T>(obs: Observable<T>, done: (v: T) => void): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    obs.subscribe({
      next: (v) => { this.busy.set(false); done(v); },
      error: (e) => { this.busy.set(false); this.error.set(apiErrorMessage(e)); },
    });
  }
}
