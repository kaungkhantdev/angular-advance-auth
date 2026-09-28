import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import type { AuthResponse, CurrentUser } from './auth.models';
import { safeReturnUrl } from './auth.guards';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { HasPermissionDirective } from './has-permission.directive';

const user = (permissions: CurrentUser['permissions']): CurrentUser => ({
  id: 'u1', email: 'a@example.com', name: 'A', emailVerified: true, mfaEnabled: false,
  roles: ['user'], permissions, createdAt: 0,
});
const authResponse = (token: string, permissions: CurrentUser['permissions'] = []): AuthResponse =>
  ({ accessToken: token, expiresIn: 900, user: user(permissions) });

describe('safeReturnUrl', () => {
  it('allows in-app paths only', () => {
    expect(safeReturnUrl('/admin/users')).toBe('/admin/users');
    expect(safeReturnUrl('//evil.example')).toBe('/');
    expect(safeReturnUrl('/\\evil.example')).toBe('/');
    expect(safeReturnUrl('https://evil.example')).toBe('/');
    expect(safeReturnUrl(null)).toBe('/');
  });
});

describe('auth interceptor + service', () => {
  let http: HttpClient;
  let ctrl: HttpTestingController;
  let auth: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideRouter([]), provideHttpClient(withInterceptors([authInterceptor])), provideHttpClientTesting()],
    });
    http = TestBed.inject(HttpClient);
    ctrl = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => ctrl.verify());

  async function signIn(token: string) {
    const p = firstValueFrom(auth.login('a@example.com', 'pw'));
    ctrl.expectOne('/api/auth/login').flush(authResponse(token));
    await p;
  }

  it('attaches the bearer token to API calls but never to third-party URLs', async () => {
    await signIn('t1');
    http.get('/api/articles').subscribe();
    http.get('https://cdn.example.com/x.json').subscribe();
    expect(ctrl.expectOne('/api/articles').request.headers.get('Authorization')).toBe('Bearer t1');
    expect(ctrl.expectOne('https://cdn.example.com/x.json').request.headers.has('Authorization')).toBe(false);
  });

  it('refreshes once for concurrent 401s and replays the requests', async () => {
    await signIn('old');
    const a = firstValueFrom(http.get('/api/a'));
    const b = firstValueFrom(http.get('/api/b'));
    const expired = { error: { code: 'TOKEN_EXPIRED', message: 'expired' } };
    ctrl.expectOne('/api/a').flush(expired, { status: 401, statusText: 'Unauthorized' });
    ctrl.expectOne('/api/b').flush(expired, { status: 401, statusText: 'Unauthorized' });

    const refresh = ctrl.expectOne('/api/auth/refresh');
    expect(refresh.request.headers.get('X-CSRF-Protection')).toBe('1');
    expect(refresh.request.withCredentials).toBe(true);
    refresh.flush(authResponse('new'));

    const retries = ctrl.match((r) => r.url === '/api/a' || r.url === '/api/b');
    expect(retries.length).toBe(2);
    for (const r of retries) {
      expect(r.request.headers.get('Authorization')).toBe('Bearer new');
      r.flush({ ok: true });
    }
    await Promise.all([a, b]);
  });

  it('never stores tokens in web storage', async () => {
    await signIn('secret-token');
    const dump = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage });
    expect(dump).not.toContain('secret-token');
  });
});

@Component({
  imports: [HasPermissionDirective],
  template: `<span *hasPermission="'users:read'; else denied" id="yes">yes</span><ng-template #denied><span id="no">no</span></ng-template>`,
})
class Host {}

describe('HasPermissionDirective', () => {
  it('renders based on permissions and reacts to changes', async () => {
    TestBed.configureTestingModule({
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const auth = TestBed.inject(AuthService);
    const ctrl = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    expect(fixture.nativeElement.querySelector('#no')).toBeTruthy();

    const p = firstValueFrom(auth.login('a@example.com', 'pw'));
    ctrl.expectOne('/api/auth/login').flush(authResponse('t', ['users:read']));
    await p;
    await fixture.whenStable();
    expect(fixture.nativeElement.querySelector('#yes')).toBeTruthy();
    expect(fixture.nativeElement.querySelector('#no')).toBeFalsy();
  });
});
