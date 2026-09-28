import type { Routes } from '@angular/router';
import { authGuard, guestGuard, requireAnyPermission, requirePermissions } from './core/auth/auth.guards';
import { Shell } from './layout/shell';

export const routes: Routes = [
  // ---- Public (guests only; the guard sits on each leaf so "/" can never redirect-loop) ----
  { path: 'login', title: 'Sign in', canMatch: [guestGuard], loadComponent: () => import('./features/auth/login').then((m) => m.Login) },
  { path: 'register', title: 'Create account', canMatch: [guestGuard], loadComponent: () => import('./features/auth/register').then((m) => m.Register) },
  { path: 'forgot-password', title: 'Reset password', canMatch: [guestGuard], loadComponent: () => import('./features/auth/forgot-password').then((m) => m.ForgotPassword) },
  // Token links from e-mails work whether or not someone is signed in.
  { path: 'verify-email', title: 'Verify e-mail', loadComponent: () => import('./features/auth/verify-email').then((m) => m.VerifyEmail) },
  { path: 'reset-password', title: 'Choose password', loadComponent: () => import('./features/auth/reset-password').then((m) => m.ResetPassword) },

  // ---- Authenticated app ----
  {
    path: '',
    component: Shell,
    canMatch: [authGuard],
    children: [
      { path: '', title: 'Dashboard', loadComponent: () => import('./features/dashboard/dashboard').then((m) => m.Dashboard) },
      { path: 'account', title: 'Account security', loadComponent: () => import('./features/account/account').then((m) => m.Account) },
      {
        path: 'articles',
        canActivate: [requirePermissions('articles:read')],
        children: [
          { path: '', title: 'Articles', loadComponent: () => import('./features/articles/articles-list').then((m) => m.ArticlesList) },
          {
            path: 'new',
            title: 'New article',
            canActivate: [requirePermissions('articles:create')],
            loadComponent: () => import('./features/articles/article-detail').then((m) => m.ArticleDetail),
          },
          { path: ':id', title: 'Article', loadComponent: () => import('./features/articles/article-detail').then((m) => m.ArticleDetail) },
          {
            path: ':id/edit',
            title: 'Edit article',
            data: { mode: 'edit' },
            canActivate: [requireAnyPermission('articles:update:own', 'articles:update:any')],
            loadComponent: () => import('./features/articles/article-detail').then((m) => m.ArticleDetail),
          },
        ],
      },
      {
        path: 'admin',
        children: [
          {
            path: 'users',
            canActivate: [requirePermissions('users:read')],
            children: [
              { path: '', title: 'Users', loadComponent: () => import('./features/admin/users-list').then((m) => m.UsersList) },
              { path: ':id', title: 'User', loadComponent: () => import('./features/admin/user-detail').then((m) => m.UserDetail) },
            ],
          },
          {
            path: 'roles',
            canActivate: [requirePermissions('roles:read')],
            children: [
              { path: '', title: 'Roles', loadComponent: () => import('./features/admin/roles-list').then((m) => m.RolesList) },
              {
                path: 'new',
                title: 'New role',
                canActivate: [requirePermissions('roles:create')],
                loadComponent: () => import('./features/admin/role-editor').then((m) => m.RoleEditor),
              },
              { path: ':id', title: 'Role', loadComponent: () => import('./features/admin/role-editor').then((m) => m.RoleEditor) },
            ],
          },
          {
            path: 'audit',
            title: 'Audit log',
            canActivate: [requirePermissions('audit:read')],
            loadComponent: () => import('./features/admin/audit-log').then((m) => m.AuditLog),
          },
        ],
      },
      { path: 'forbidden', title: 'Access denied', loadComponent: () => import('./features/errors/error-pages').then((m) => m.Forbidden) },
    ],
  },

  // Unknown URL: signed-out users hit the auth guard above and land on /login.
  { path: '**', title: 'Not found', loadComponent: () => import('./features/errors/error-pages').then((m) => m.NotFound) },
];
