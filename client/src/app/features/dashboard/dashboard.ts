import { Component, computed, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { HasPermissionDirective } from '../../core/auth/has-permission.directive';

@Component({
  selector: 'app-dashboard',
  imports: [RouterLink, HasPermissionDirective],
  template: `
    @if (auth.user(); as user) {
      <div class="page-header">
        <h1>Hello, {{ user.name }}</h1>
        <p class="muted">Signed in as {{ user.email }}</p>
      </div>

      @if (!user.mfaEnabled) {
        <div class="alert alert-warning spread" style="margin-bottom: 1rem">
          <span>Protect your account with two-factor authentication.</span>
          <a routerLink="/account" class="btn btn-sm">Set up 2FA</a>
        </div>
      }

      <div class="grid">
        <section class="card">
          <h2>Your roles</h2>
          <div class="row">
            @for (role of user.roles; track role) { <span class="badge badge-primary">{{ role }}</span> }
          </div>
        </section>

        <section class="card">
          <h2>Quick links</h2>
          <div class="stack-sm">
            <a *hasPermission="'articles:read'" routerLink="/articles">Articles →</a>
            <a *hasPermission="'users:read'" routerLink="/admin/users">Manage users →</a>
            <a *hasPermission="'roles:read'" routerLink="/admin/roles">Roles & permissions →</a>
            <a *hasPermission="'audit:read'" routerLink="/admin/audit">Security audit log →</a>
            <a routerLink="/account">Account security →</a>
          </div>
        </section>
      </div>

      <section class="card" style="margin-top: 1rem">
        <h2>Effective permissions <span class="badge">{{ user.permissions.length }}</span></h2>
        <p class="muted small">The union of permissions from all of your roles, as enforced by the API.</p>
        @for (group of grouped(); track group.resource) {
          <div class="perm-group">
            <strong>{{ group.resource }}</strong>
            <div class="row">
              @for (p of group.actions; track p) { <code class="badge">{{ p }}</code> }
            </div>
          </div>
        }
      </section>
    }
  `,
  styles: `
    .perm-group { display: grid; grid-template-columns: 7rem 1fr; gap: .5rem; padding: .5rem 0; border-top: 1px solid var(--border); align-items: center; }
    .perm-group strong { text-transform: capitalize; font-size: .9rem; }
  `,
})
export class Dashboard {
  protected readonly auth = inject(AuthService);
  protected readonly grouped = computed(() => {
    const map = new Map<string, string[]>();
    for (const p of this.auth.user()?.permissions ?? []) {
      const [resource, ...rest] = p.split(':');
      map.set(resource!, [...(map.get(resource!) ?? []), rest.join(':')]);
    }
    return [...map].map(([resource, actions]) => ({ resource, actions }));
  });
}
