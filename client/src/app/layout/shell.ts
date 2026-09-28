import { Component, inject, signal } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../core/auth/auth.service';
import { HasPermissionDirective } from '../core/auth/has-permission.directive';

/** Authenticated application frame: navigation is filtered by the user's permissions. */
@Component({
  selector: 'app-shell',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, HasPermissionDirective],
  template: `
    <header class="topbar">
      <div class="topbar-inner">
        <a routerLink="/" class="logo"><span class="brand-mark">A</span><span class="hide-sm">Advance Auth</span></a>

        <button class="btn btn-ghost menu-toggle" (click)="menuOpen.set(!menuOpen())" [attr.aria-expanded]="menuOpen()" aria-label="Toggle navigation">☰</button>

        <nav [class.open]="menuOpen()" (click)="menuOpen.set(false)">
          <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }">Dashboard</a>
          <a *hasPermission="'articles:read'" routerLink="/articles" routerLinkActive="active">Articles</a>
          <a *hasPermission="'users:read'" routerLink="/admin/users" routerLinkActive="active">Users</a>
          <a *hasPermission="'roles:read'" routerLink="/admin/roles" routerLinkActive="active">Roles</a>
          <a *hasPermission="'audit:read'" routerLink="/admin/audit" routerLinkActive="active">Audit log</a>
        </nav>

        @if (auth.user(); as user) {
          <div class="user">
            <a routerLink="/account" class="user-link" routerLinkActive="active">
              <span class="avatar">{{ user.name.charAt(0).toUpperCase() }}</span>
              <span class="hide-sm">{{ user.name }}</span>
            </a>
            <button class="btn btn-sm" (click)="logout()">Sign out</button>
          </div>
        }
      </div>
    </header>

    <main class="content">
      <router-outlet />
    </main>
  `,
  styles: `
    .topbar { background: var(--surface); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 10; }
    .topbar-inner { max-width: 1120px; margin: 0 auto; padding: .6rem 1rem; display: flex; align-items: center; gap: 1.25rem; }
    .logo { display: flex; align-items: center; gap: .5rem; font-weight: 700; color: var(--text); text-decoration: none; }
    nav { display: flex; gap: .25rem; flex: 1; }
    nav a { padding: .4rem .7rem; border-radius: 8px; color: var(--muted); font-weight: 500; text-decoration: none; }
    nav a:hover { background: var(--surface-2); color: var(--text); }
    nav a.active { background: var(--primary-soft); color: var(--primary); }
    .user { display: flex; align-items: center; gap: .6rem; }
    .user-link { display: flex; align-items: center; gap: .5rem; color: var(--text); text-decoration: none; padding: .25rem .5rem; border-radius: 8px; }
    .user-link.active, .user-link:hover { background: var(--surface-2); }
    .avatar { width: 28px; height: 28px; border-radius: 50%; background: var(--primary-soft); color: var(--primary); display: grid; place-items: center; font-weight: 700; font-size: .85rem; }
    .content { max-width: 1120px; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
    .menu-toggle { display: none; }
    @media (max-width: 760px) {
      .menu-toggle { display: inline-flex; order: 3; }
      .user { margin-left: auto; }
      nav { display: none; position: absolute; top: 100%; left: 0; right: 0; flex-direction: column; background: var(--surface); border-bottom: 1px solid var(--border); padding: .5rem 1rem; }
      nav.open { display: flex; }
    }
  `,
})
export class Shell {
  protected readonly auth = inject(AuthService);
  protected readonly menuOpen = signal(false);

  protected logout(): void {
    void this.auth.logout();
  }
}
