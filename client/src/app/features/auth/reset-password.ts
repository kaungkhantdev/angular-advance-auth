import { Component, inject, OnInit, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AccountApi } from '../../core/api/account.api';
import { apiErrorMessage } from '../../core/http/errors';
import { PasswordStrength } from './password-strength';
import { ensureValid } from '../../core/forms';

@Component({
  selector: 'app-reset-password',
  imports: [ReactiveFormsModule, RouterLink, PasswordStrength],
  template: `
    <div class="auth-page">
      <div class="card auth-card">
        <div class="brand"><span class="brand-mark">A</span> Advance Auth</div>
        <h1>Choose a new password</h1>
        @if (done()) {
          <div class="alert alert-success">{{ done() }}</div>
          <p class="footer"><a routerLink="/login" class="btn btn-primary btn-block">Sign in</a></p>
        } @else if (!token) {
          <div class="alert alert-error">This link is missing its token. Request a new one.</div>
          <p class="footer"><a routerLink="/forgot-password">Request reset link</a></p>
        } @else {
          <form [formGroup]="form" (ngSubmit)="submit()" class="stack" novalidate>
            @if (error()) { <div class="alert alert-error">{{ error() }}</div> }
            <div class="field">
              <label for="password">New password</label>
              <input id="password" type="password" formControlName="password" autocomplete="new-password" autofocus />
              <app-password-strength [password]="password() ?? ''" />
            </div>
            <div class="field">
              <label for="confirm">Confirm password</label>
              <input id="confirm" type="password" formControlName="confirm" autocomplete="new-password" />
              @if (mismatch()) { <span class="error-text">Passwords don't match</span> }
            </div>
            <p class="small muted">All devices signed in to your account will be signed out.</p>
            <button class="btn btn-primary btn-block" [disabled]="busy()">Update password</button>
          </form>
        }
      </div>
    </div>
  `,
})
export class ResetPassword implements OnInit {
  private readonly api = inject(AccountApi);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  protected token: string | null = null;
  protected readonly form = inject(NonNullableFormBuilder).group({
    password: ['', [Validators.required, Validators.minLength(12), Validators.maxLength(128)]],
    confirm: ['', Validators.required],
  });
  protected readonly password = toSignal(this.form.controls.password.valueChanges);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly done = signal<string | null>(null);
  protected readonly mismatch = signal(false);

  ngOnInit(): void {
    this.token = this.route.snapshot.queryParamMap.get('token');
    void this.router.navigate([], { queryParams: {}, replaceUrl: true });
  }

  protected submit(): void {
    if (!ensureValid(this.form)) return;
    const { password, confirm } = this.form.getRawValue();
    this.mismatch.set(password !== confirm);
    if (this.mismatch() || !this.token) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.resetPassword(this.token, password).subscribe({
      next: (r) => this.done.set(r.message),
      error: (err) => { this.busy.set(false); this.error.set(apiErrorMessage(err)); },
    });
  }
}
