import { inject } from '@angular/core';
import { Router, type CanActivateFn, type CanMatchFn } from '@angular/router';
import { AuthService } from './auth.service';
import type { Permission } from './permissions';

/** Only allow same-app relative paths as post-login redirects (prevents open redirects). */
export function safeReturnUrl(url: unknown): string {
  return typeof url === 'string' && url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\') ? url : '/';
}

/** Signed-in users only; everyone else is sent to /login with a return URL. */
export const authGuard: CanMatchFn = (_route, segments) => {
  const auth = inject(AuthService);
  if (auth.isAuthenticated()) return true;
  const returnUrl = '/' + segments.map((s) => s.path).join('/');
  return inject(Router).createUrlTree(['/login'], { queryParams: returnUrl !== '/' ? { returnUrl } : {} });
};

/** Pages like /login and /register make no sense while signed in. */
export const guestGuard: CanMatchFn = () =>
  inject(AuthService).isAuthenticated() ? inject(Router).createUrlTree(['/']) : true;

/**
 * Route-level RBAC for the UI. Requires ALL listed permissions.
 * This only improves UX — the API independently enforces the same rules.
 */
export function requirePermissions(...permissions: Permission[]): CanActivateFn {
  return () => (inject(AuthService).hasPermission(...permissions) ? true : inject(Router).createUrlTree(['/forbidden']));
}

export function requireAnyPermission(...permissions: Permission[]): CanActivateFn {
  return () => (inject(AuthService).hasAnyPermission(...permissions) ? true : inject(Router).createUrlTree(['/forbidden']));
}
