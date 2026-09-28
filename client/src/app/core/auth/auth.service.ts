import { HttpClient, HttpContext, HttpContextToken } from '@angular/common/http';
import { computed, DestroyRef, inject, Service, signal } from '@angular/core';
import { Router } from '@angular/router';
import {
  catchError, finalize, firstValueFrom, map, Observable, retry, shareReplay, tap, throwError, timer,
} from 'rxjs';
import { apiErrorCode } from '../http/errors';
import type { AuthResponse, CurrentUser, LoginResponse } from './auth.models';
import type { Permission } from './permissions';

/** Marks requests the interceptor must not try to refresh-and-retry (avoids loops). */
export const SKIP_AUTH_REFRESH = new HttpContextToken<boolean>(() => false);
const skipRefresh = () => new HttpContext().set(SKIP_AUTH_REFRESH, true);

/** Must match the server's CSRF guard on cookie-authenticated endpoints. */
const CSRF_HEADERS = { 'X-CSRF-Protection': '1' };

type BroadcastMessage = { type: 'logout' } | { type: 'login' };

/**
 * Session state for the SPA.
 *
 * Token handling follows current browser-app best practice:
 *  - The access token lives only in memory (never localStorage/sessionStorage), so
 *    an XSS payload can't lift a long-lived credential from storage.
 *  - The refresh token is an HttpOnly cookie the JS never sees; on page load we call
 *    /refresh to silently restore the session.
 *  - Refreshes are single-flight: concurrent 401s share one refresh request.
 *  - Logout is broadcast to other tabs.
 */
@Service()
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);

  private readonly _user = signal<CurrentUser | null>(null);
  private accessToken: string | null = null;
  private refresh$: Observable<string> | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly channel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('auth') : null;

  readonly user = this._user.asReadonly();
  readonly isAuthenticated = computed(() => this._user() !== null);
  private readonly permissionSet = computed(() => new Set<Permission>(this._user()?.permissions ?? []));

  constructor() {
    this.channel?.addEventListener('message', (e: MessageEvent<BroadcastMessage>) => {
      if (e.data.type === 'logout') this.endSession('signed-out-elsewhere');
      if (e.data.type === 'login' && !this.isAuthenticated()) void this.restoreSession();
    });
    inject(DestroyRef).onDestroy(() => this.channel?.close());
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  hasPermission(...required: Permission[]): boolean {
    const set = this.permissionSet();
    return required.every((p) => set.has(p));
  }

  hasAnyPermission(...required: Permission[]): boolean {
    const set = this.permissionSet();
    return required.some((p) => set.has(p));
  }

  // ---------------------------------------------------------------------------
  // Sign-in flows
  // ---------------------------------------------------------------------------

  login(email: string, password: string): Observable<LoginResponse> {
    return this.http
      .post<LoginResponse>('/api/auth/login', { email, password }, { context: skipRefresh() })
      .pipe(tap((res) => { if (!res.mfaRequired) this.startSession(res, true); }));
  }

  verifyMfa(mfaToken: string, code: string): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>('/api/auth/login/mfa', { mfaToken, code }, { context: skipRefresh() })
      .pipe(tap((res) => this.startSession(res, true)));
  }

  /** Called once at app start-up: silently resumes the session from the refresh cookie. */
  async restoreSession(): Promise<void> {
    try {
      await firstValueFrom(this.refresh());
    } catch {
      // No valid session — the user will be sent to /login by the guards.
    }
  }

  /**
   * Exchanges the refresh cookie for a new access token. Single-flight: callers
   * arriving while a refresh is running share its result.
   */
  refresh(): Observable<string> {
    this.refresh$ ??= this.http
      .post<AuthResponse>('/api/auth/refresh', {}, { headers: CSRF_HEADERS, context: skipRefresh() })
      .pipe(
        // Another tab rotated the cookie at the same moment; the browser now holds the
        // new one, so a single quick retry succeeds.
        retry({ count: 1, delay: (err) => (apiErrorCode(err) === 'REFRESH_RACE' ? timer(250) : throwError(() => err)) }),
        tap((res) => this.startSession(res, false)),
        map((res) => res.accessToken),
        catchError((err) => {
          this.clearState();
          return throwError(() => err);
        }),
        finalize(() => (this.refresh$ = null)),
        shareReplay({ bufferSize: 1, refCount: false }),
      );
    return this.refresh$;
  }

  async logout(): Promise<void> {
    try {
      await firstValueFrom(this.http.post('/api/auth/logout', {}, { headers: CSRF_HEADERS, context: skipRefresh() }));
    } finally {
      this.channel?.postMessage({ type: 'logout' } satisfies BroadcastMessage);
      this.endSession();
    }
  }

  async logoutEverywhere(): Promise<void> {
    await firstValueFrom(this.http.post('/api/auth/logout-all', {}));
    this.channel?.postMessage({ type: 'logout' } satisfies BroadcastMessage);
    this.endSession();
  }

  /** Re-fetches the profile, e.g. after roles or MFA status changed. */
  async reloadUser(): Promise<void> {
    this._user.set(await firstValueFrom(this.http.get<CurrentUser>('/api/auth/me')));
  }

  /** Session is gone server-side (revoked, expired, reuse detected): clean up and go to login. */
  endSession(reason?: string): void {
    const wasSignedIn = this.isAuthenticated();
    this.clearState();
    if (wasSignedIn || reason) {
      void this.router.navigate(['/login'], { queryParams: reason ? { reason } : {} });
    }
  }

  // ---------------------------------------------------------------------------

  private startSession(res: AuthResponse, isNewLogin: boolean): void {
    this.accessToken = res.accessToken;
    this._user.set(res.user);
    this.scheduleProactiveRefresh(res.expiresIn);
    if (isNewLogin) this.channel?.postMessage({ type: 'login' } satisfies BroadcastMessage);
  }

  /** Refresh shortly before expiry so active users never see a failed request. */
  private scheduleProactiveRefresh(expiresInSeconds: number): void {
    clearTimeout(this.refreshTimer);
    const ms = Math.max(expiresInSeconds * 1000 * 0.8, 5_000);
    this.refreshTimer = setTimeout(() => this.refresh().subscribe({ error: () => this.endSession('expired') }), ms);
  }

  private clearState(): void {
    clearTimeout(this.refreshTimer);
    this.accessToken = null;
    this._user.set(null);
  }
}
