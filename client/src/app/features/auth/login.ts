import { Component, computed, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AccountApi } from '../../core/api/account.api';
import { safeReturnUrl } from '../../core/auth/auth.guards';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorCode, apiErrorMessage } from '../../core/http/errors';
import { ensureValid } from '../../core/forms';

const REASONS: Record<string, string> = {
  expired: 'Your session expired. Please sign in again.',
  revoked: 'Your session was ended (signed out remotely or by an administrator).',
  'signed-out-elsewhere': 'You signed out in another tab.',
};

@Component({
  selector: 'app-login',
  imports: [ReactiveFormsModule, RouterLink],
  template: `
    <div class="auth-page">
      <div class="card auth-card">
        <div class="brand"><span class="brand-mark">A</span> Advance Auth</div>

        @if (!mfaToken()) {
          <h1>Sign in</h1>
          <p class="muted">Welcome back. Enter your credentials to continue.</p>

          <form [formGroup]="form" (ngSubmit)="submit()" class="stack" novalidate>
            @if (reasonMessage(); as msg) { <div class="alert alert-info">{{ msg }}</div> }
            @if (error()) { <div class="alert alert-error" role="alert">{{ error() }}</div> }
            @if (needsVerification()) {
              <div class="alert alert-warning">
                Didn't get the e-mail?
                <button type="button" class="btn btn-sm" (click)="resend()" [disabled]="busy()">Resend link</button>
              </div>
            }
            @if (info()) { <div class="alert alert-success">{{ info() }}</div> }

            <div class="field">
              <label for="email">E-mail</label>
              <input id="email" type="email" formControlName="email" autocomplete="username" autofocus />
            </div>
            <div class="field">
              <div class="spread"><label for="password">Password</label><a routerLink="/forgot-password" class="small">Forgot password?</a></div>
              <input id="password" type="password" formControlName="password" autocomplete="current-password" />
            </div>
            <button class="btn btn-primary btn-block" type="submit" [disabled]="busy()">
              {{ busy() ? 'Signing in…' : 'Sign in' }}
            </button>
          </form>
          <p class="footer">No account? <a routerLink="/register">Create one</a></p>
        } @else {
          <h1>Two-factor authentication</h1>
          <p class="muted">
            @if (useRecovery()) { Enter one of your saved recovery codes. }
            @else { Enter the 6-digit code from your authenticator app. }
          </p>
          <form [formGroup]="mfaForm" (ngSubmit)="submitMfa()" class="stack" novalidate>
            @if (error()) { <div class="alert alert-error" role="alert">{{ error() }}</div> }
            <div class="field">
              <label for="code">{{ useRecovery() ? 'Recovery code' : 'Authentication code' }}</label>
              <input id="code" type="text" formControlName="code" autocomplete="one-time-code"
                     [attr.inputmode]="useRecovery() ? 'text' : 'numeric'" [attr.maxlength]="useRecovery() ? 11 : 6" autofocus />
            </div>
            <button class="btn btn-primary btn-block" type="submit" [disabled]="busy()">Verify</button>
            <div class="spread small">
              <button type="button" class="btn btn-ghost btn-sm" (click)="toggleRecovery()">
                {{ useRecovery() ? 'Use authenticator app' : 'Use a recovery code' }}
              </button>
              <button type="button" class="btn btn-ghost btn-sm" (click)="cancelMfa()">Back</button>
            </div>
          </form>
        }
      </div>
    </div>
  `,
})
export class Login {
  private readonly auth = inject(AuthService);
  private readonly account = inject(AccountApi);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly fb = inject(NonNullableFormBuilder);

  protected readonly form = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required],
  });
  protected readonly mfaForm = this.fb.group({ code: ['', [Validators.required, Validators.minLength(6)]] });

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly info = signal<string | null>(null);
  protected readonly needsVerification = signal(false);
  protected readonly mfaToken = signal<string | null>(null);
  protected readonly useRecovery = signal(false);
  protected readonly reasonMessage = computed(() => REASONS[this.route.snapshot.queryParamMap.get('reason') ?? ''] ?? null);

  protected submit(): void {
    if (!ensureValid(this.form)) return;
    this.reset();
    const { email, password } = this.form.getRawValue();
    this.auth.login(email, password).subscribe({
      next: (res) => {
        this.busy.set(false);
        if (res.mfaRequired) this.mfaToken.set(res.mfaToken);
        else this.redirect();
      },
      error: (err) => {
        this.busy.set(false);
        this.needsVerification.set(apiErrorCode(err) === 'EMAIL_NOT_VERIFIED');
        this.error.set(apiErrorMessage(err));
        this.form.controls.password.reset();
      },
    });
  }

  protected submitMfa(): void {
    const token = this.mfaToken();
    if (!token || !ensureValid(this.mfaForm)) return;
    this.reset();
    this.auth.verifyMfa(token, this.mfaForm.getRawValue().code.trim()).subscribe({
      next: () => this.redirect(),
      error: (err) => {
        this.busy.set(false);
        const code = apiErrorCode(err);
        if (code === 'MFA_CHALLENGE_INVALID' || code === 'ACCOUNT_LOCKED') {
          this.cancelMfa();
        }
        this.error.set(apiErrorMessage(err));
        this.mfaForm.reset();
      },
    });
  }

  protected resend(): void {
    this.account.resendVerification(this.form.getRawValue().email).subscribe({
      next: (r) => { this.needsVerification.set(false); this.error.set(null); this.info.set(r.message); },
    });
  }

  protected toggleRecovery(): void {
    this.useRecovery.update((v) => !v);
    this.mfaForm.reset();
  }

  protected cancelMfa(): void {
    this.mfaToken.set(null);
    this.useRecovery.set(false);
    this.mfaForm.reset();
    this.form.controls.password.reset();
  }

  private reset(): void {
    this.busy.set(true);
    this.error.set(null);
    this.info.set(null);
  }

  private redirect(): void {
    void this.router.navigateByUrl(safeReturnUrl(this.route.snapshot.queryParamMap.get('returnUrl')));
  }
}
