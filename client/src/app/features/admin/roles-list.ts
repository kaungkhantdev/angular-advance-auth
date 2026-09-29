import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { RolesApi } from '../../core/api/admin.api';
import type { Role } from '../../core/api/api.models';
import { HasPermissionDirective } from '../../core/auth/has-permission.directive';
import { apiErrorMessage } from '../../core/http/errors';

@Component({
  selector: 'app-roles-list',
  imports: [RouterLink, HasPermissionDirective],
  template: `
    <div class="page-header spread">
      <div>
        <h1>Roles & permissions</h1>
        <p class="muted">System roles come with sensible defaults you can adjust. Custom roles can be composed from the permission catalog.</p>
      </div>
      <a *hasPermission="'roles:create'" routerLink="/admin/roles/new" class="btn btn-primary">New role</a>
    </div>
    @if (error()) { <div class="alert alert-error">{{ error() }}</div> }

    <div class="grid">
      @for (r of roles(); track r.id) {
        <a class="card role-card" [routerLink]="['/admin/roles', r.id]">
          <div class="spread">
            <h2 style="margin: 0">{{ r.name }}</h2>
            @if (r.isSystem) { <span class="badge">system</span> } @else { <span class="badge badge-primary">custom</span> }
          </div>
          <p class="small muted">{{ r.description || 'No description' }}</p>
          <div class="row small">
            <span><strong>{{ r.effectivePermissions.length }}</strong> permissions</span>
            <span class="muted">·</span>
            <span><strong>{{ r.userCount }}</strong> users</span>
          </div>
        </a>
      }
    </div>
  `,
  styles: `.role-card { color: inherit; text-decoration: none !important; transition: border-color .15s; } .role-card:hover { border-color: var(--primary); }`,
})
export class RolesList implements OnInit {
  private readonly api = inject(RolesApi);
  protected readonly roles = signal<Role[]>([]);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.list().subscribe({ next: (r) => this.roles.set(r), error: (e) => this.error.set(apiErrorMessage(e)) });
  }
}
