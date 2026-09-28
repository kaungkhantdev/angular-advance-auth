import { DatePipe } from '@angular/common';
import { Component, inject, OnInit, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { firstValueFrom } from 'rxjs';
import { AccountApi } from '../../core/api/account.api';
import type { Session } from '../../core/api/api.models';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../core/http/errors';
import { PasswordStrength } from '../auth/password-strength';
import { MfaSettings } from './mfa-settings';
import { ensureValid } from '../../core/forms';

@Component({
  selector: 'app-account',
  imports: [ReactiveFormsModule, DatePipe, PasswordStrength, MfaSettings],
  template: `
    <div class="page-header">
      <h1>Account security</h1>
      <p class="muted">Manage your password, two-factor authentication and signed-in devices.</p>
    </div>

    <div class="stack">
      <app-mfa-settings />

      <section class="card">
        <h2>Change password</h2>
        <form [formGroup]="pwForm" (ngSubmit)="changePassword()" class="stack" style="max-width: 420px" novalidate>
          @if (pwError()) { <div class="alert alert-error">{{ pwError() }}</div> }
          @if (pwDone()) { <div class="alert alert-success">{{ pwDone() }}</div> }
          <div class="field">
            <label for="cur">Current password</label>
            <input id="cur" type="password" formControlName="currentPassword" autocomplete="current-password" />
          </div>
          <div class="field">
            <label for="new">New password</label>
            <input id="new" type="password" formControlName="newPassword" autocomplete="new-password" />
            <app-password-strength [password]="newPassword() ?? ''" />
          </div>
          <div><button class="btn btn-primary" [disabled]="pwBusy()">Update password</button></div>
        </form>
      </section>

      <section class="card">
        <div class="spread">
          <h2>Signed-in devices</h2>
          <button class="btn btn-danger btn-sm" (click)="logoutEverywhere()">Sign out everywhere</button>
        </div>
        @if (sessionsError()) { <div class="alert alert-error">{{ sessionsError() }}</div> }
        <div class="table-wrap">
          <table>
            <thead><tr><th>Device</th><th class="hide-sm">IP</th><th>Last active</th><th class="hide-sm">Signed in</th><th></th></tr></thead>
            <tbody>
              @for (s of sessions(); track s.id) {
                <tr>
                  <td>
                    {{ describeAgent(s.userAgent) }}
                    @if (s.current) { <span class="badge badge-success">This device</span> }
                    @if (s.mfaVerified) { <span class="badge">2FA</span> }
                  </td>
                  <td class="hide-sm mono">{{ s.ip ?? '—' }}</td>
                  <td>{{ s.lastUsedAt | date: 'short' }}</td>
                  <td class="hide-sm">{{ s.createdAt | date: 'short' }}</td>
                  <td style="text-align: right">
                    @if (!s.current) { <button class="btn btn-sm" (click)="revoke(s)">Sign out</button> }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class Account implements OnInit {
  private readonly api = inject(AccountApi);
  private readonly auth = inject(AuthService);
  private readonly fb = inject(NonNullableFormBuilder);

  protected readonly pwForm = this.fb.group({
    currentPassword: ['', Validators.required],
    newPassword: ['', [Validators.required, Validators.minLength(12), Validators.maxLength(128)]],
  });
  protected readonly newPassword = toSignal(this.pwForm.controls.newPassword.valueChanges);
  protected readonly pwBusy = signal(false);
  protected readonly pwError = signal<string | null>(null);
  protected readonly pwDone = signal<string | null>(null);

  protected readonly sessions = signal<Session[]>([]);
  protected readonly sessionsError = signal<string | null>(null);

  ngOnInit(): void {
    this.loadSessions();
  }

  protected changePassword(): void {
    if (!ensureValid(this.pwForm)) return;
    this.pwBusy.set(true);
    this.pwError.set(null);
    this.pwDone.set(null);
    const { currentPassword, newPassword } = this.pwForm.getRawValue();
    this.api.changePassword(currentPassword, newPassword).subscribe({
      next: (r) => {
        this.pwBusy.set(false);
        this.pwDone.set(r.message);
        this.pwForm.reset();
        this.loadSessions();
      },
      error: (err) => { this.pwBusy.set(false); this.pwError.set(apiErrorMessage(err)); },
    });
  }

  protected revoke(s: Session): void {
    this.api.revokeSession(s.id).subscribe({
      next: () => this.sessions.update((list) => list.filter((x) => x.id !== s.id)),
      error: (err) => this.sessionsError.set(apiErrorMessage(err)),
    });
  }

  protected async logoutEverywhere(): Promise<void> {
    if (!confirm('Sign out of every device, including this one?')) return;
    await this.auth.logoutEverywhere();
  }

  protected describeAgent(ua: string | null): string {
    if (!ua) return 'Unknown device';
    const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
    const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : '';
    return os ? `${browser} on ${os}` : browser;
  }

  private async loadSessions(): Promise<void> {
    try {
      this.sessions.set(await firstValueFrom(this.api.sessions()));
    } catch (err) {
      this.sessionsError.set(apiErrorMessage(err));
    }
  }
}
