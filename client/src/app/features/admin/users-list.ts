import { DatePipe } from '@angular/common';
import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule, NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { RolesApi, UsersApi } from '../../core/api/admin.api';
import type { AdminUser, Role } from '../../core/api/api.models';
import { AuthService } from '../../core/auth/auth.service';
import { HasPermissionDirective } from '../../core/auth/has-permission.directive';
import { apiErrorMessage } from '../../core/http/errors';
import { canDelegate } from './delegation';
import { ensureValid } from '../../core/forms';

const PAGE_SIZE = 20;

@Component({
  selector: 'app-users-list',
  imports: [RouterLink, DatePipe, FormsModule, ReactiveFormsModule, HasPermissionDirective],
  template: `
    <div class="page-header spread">
      <div>
        <h1>Users</h1>
        <p class="muted">{{ total() }} account(s)</p>
      </div>
      <button *hasPermission="'users:create'" class="btn btn-primary" (click)="showInvite.set(!showInvite())">
        {{ showInvite() ? 'Close' : 'Invite user' }}
      </button>
    </div>

    @if (showInvite()) {
      <form class="card stack" [formGroup]="invite" (ngSubmit)="create()" style="margin-bottom: 1rem">
        <h2>Invite a user</h2>
        <p class="small muted" style="margin: 0">They'll receive an e-mail link to set their own password. Admins never choose passwords for others.</p>
        @if (inviteError()) { <div class="alert alert-error">{{ inviteError() }}</div> }
        <div class="grid">
          <div class="field"><label for="i-name">Name</label><input id="i-name" type="text" formControlName="name" /></div>
          <div class="field"><label for="i-email">E-mail</label><input id="i-email" type="email" formControlName="email" /></div>
        </div>
        @if (roles().length) {
          <fieldset class="field" style="border: 0; padding: 0; margin: 0">
            <legend class="small" style="font-weight: 600; margin-bottom: .3rem">Roles (defaults to "user")</legend>
            <div class="row">
              @for (r of roles(); track r.id) {
                <label class="checkbox" [title]="delegable(r) ? r.description : 'You can only grant roles whose permissions you hold'">
                  <input type="checkbox" [disabled]="!delegable(r)" [checked]="inviteRoles().has(r.id)" (change)="toggleInviteRole(r.id)" />
                  {{ r.name }}
                </label>
              }
            </div>
          </fieldset>
        }
        <div><button class="btn btn-primary" [disabled]="busy()">Send invite</button></div>
      </form>
    }

    <div class="card">
      <input type="search" placeholder="Search by name or e-mail…" [(ngModel)]="search" (ngModelChange)="onSearch()" aria-label="Search users" style="margin-bottom: 1rem" />
      @if (error()) { <div class="alert alert-error">{{ error() }}</div> }
      <div class="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Roles</th><th>Status</th><th class="hide-sm">Last sign-in</th></tr></thead>
          <tbody>
            @for (u of users(); track u.id) {
              <tr class="clickable" (click)="open(u)">
                <td>
                  <a [routerLink]="['/admin/users', u.id]" (click)="$event.stopPropagation()">{{ u.name }}</a>
                  @if (u.id === auth.user()?.id) { <span class="badge">you</span> }
                  <div class="small muted">{{ u.email }}</div>
                </td>
                <td><div class="row">@for (r of u.roles; track r) { <span class="badge badge-primary">{{ r }}</span> }</div></td>
                <td>
                  <div class="row">
                    @if (u.status === 'disabled') { <span class="badge badge-danger">Disabled</span> }
                    @else if (u.locked) { <span class="badge badge-warning">Locked</span> }
                    @else { <span class="badge badge-success">Active</span> }
                    @if (!u.emailVerified) { <span class="badge">Unverified</span> }
                    @if (u.mfaEnabled) { <span class="badge">2FA</span> }
                  </div>
                </td>
                <td class="hide-sm small">{{ u.lastLoginAt ? (u.lastLoginAt | date: 'short') : 'Never' }}</td>
              </tr>
            } @empty {
              <tr><td colspan="4" class="muted">No users found.</td></tr>
            }
          </tbody>
        </table>
      </div>
      @if (total() > pageSize) {
        <div class="spread" style="margin-top: 1rem">
          <span class="small muted">{{ offset() + 1 }}–{{ offset() + users().length }} of {{ total() }}</span>
          <div class="row">
            <button class="btn btn-sm" [disabled]="offset() === 0" (click)="page(-1)">Previous</button>
            <button class="btn btn-sm" [disabled]="offset() + pageSize >= total()" (click)="page(1)">Next</button>
          </div>
        </div>
      }
    </div>
  `,
  styles: `.clickable { cursor: pointer; }`,
})
export class UsersList implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly usersApi = inject(UsersApi);
  private readonly rolesApi = inject(RolesApi);
  private readonly router = inject(Router);

  protected readonly pageSize = PAGE_SIZE;
  protected search = '';
  private searchTimer: ReturnType<typeof setTimeout> | undefined;

  protected readonly users = signal<AdminUser[]>([]);
  protected readonly total = signal(0);
  protected readonly offset = signal(0);
  protected readonly error = signal<string | null>(null);

  protected readonly roles = signal<Role[]>([]);
  protected readonly showInvite = signal(false);
  protected readonly inviteRoles = signal(new Set<string>());
  protected readonly inviteError = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly invite = inject(NonNullableFormBuilder).group({
    name: ['', [Validators.required, Validators.maxLength(100)]],
    email: ['', [Validators.required, Validators.email]],
  });

  ngOnInit(): void {
    this.load();
    if (this.auth.hasPermission('roles:read')) this.rolesApi.list().subscribe((r) => this.roles.set(r));
  }

  protected delegable(role: Role): boolean {
    return canDelegate(this.auth, role);
  }

  protected onSearch(): void {
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => { this.offset.set(0); this.load(); }, 250);
  }

  protected page(dir: 1 | -1): void {
    this.offset.update((o) => Math.max(0, o + dir * PAGE_SIZE));
    this.load();
  }

  protected open(u: AdminUser): void {
    void this.router.navigate(['/admin/users', u.id]);
  }

  protected toggleInviteRole(id: string): void {
    this.inviteRoles.update((s) => {
      const next = new Set(s);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  }

  protected create(): void {
    if (!ensureValid(this.invite)) return;
    this.busy.set(true);
    this.inviteError.set(null);
    this.usersApi.create({ ...this.invite.getRawValue(), roleIds: [...this.inviteRoles()] }).subscribe({
      next: (u) => {
        this.busy.set(false);
        this.invite.reset();
        this.inviteRoles.set(new Set());
        this.showInvite.set(false);
        this.users.update((list) => [u, ...list]);
        this.total.update((t) => t + 1);
      },
      error: (e) => { this.busy.set(false); this.inviteError.set(apiErrorMessage(e)); },
    });
  }

  private load(): void {
    this.usersApi.list({ search: this.search, limit: PAGE_SIZE, offset: this.offset() }).subscribe({
      next: (p) => { this.users.set(p.items); this.total.set(p.total); },
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
  }
}
