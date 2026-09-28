import { Component, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AccountApi } from '../../core/api/account.api';
import { apiErrorMessage } from '../../core/http/errors';
import { PasswordStrength } from './password-strength';
import { ensureValid } from '../../core/forms';

@Component({
  selector: 'app-register',
  imports: [ReactiveFormsModule, RouterLink, PasswordStrength],
  template: `
    <div class="auth-page">
      <div class="card auth-card">
        <div class="brand"><span class="brand-mark">A</span> Advance Auth</div>
        @if (done()) {
          <h1>Check your inbox</h1>
          <div class="alert alert-success">{{ done() }}</div>
          <p class="muted small">In development the verification link is printed in the API server console.</p>
          <p class="footer"><a routerLink="/login">Back to sign in</a></p>
        } @else {
          <h1>Create account</h1>
          <form [formGroup]="form" (ngSubmit)="submit()" class="stack" novalidate>
            @if (error()) { <div class="alert alert-error" role="alert">{{ error() }}</div> }
            <div class="field">
              <label for="name">Full name</label>
              <input id="name" type="text" formControlName="name" autocomplete="name" />
            </div>
            <div class="field">
              <label for="email">E-mail</label>
              <input id="email" type="email" formControlName="email" autocomplete="email" />
            </div>
            <div class="field">
              <label for="password">Password</label>
              <input id="password" type="password" formControlName="password" autocomplete="new-password" />
              <app-password-strength [password]="password() ?? ''" />
              <span class="hint">At least 12 characters. A passphrase of several words works well.</span>
            </div>
            <button class="btn btn-primary btn-block" type="submit" [disabled]="busy()">
              {{ busy() ? 'Creating…' : 'Create account' }}
            </button>
          </form>
          <p class="footer">Already registered? <a routerLink="/login">Sign in</a></p>
        }
      </div>
    </div>
  `,
})
export class Register {
  private readonly api = inject(AccountApi);
  protected readonly form = inject(NonNullableFormBuilder).group({
    name: ['', [Validators.required, Validators.maxLength(100)]],
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(12), Validators.maxLength(128)]],
  });
  protected readonly password = toSignal(this.form.controls.password.valueChanges);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly done = signal<string | null>(null);

  protected submit(): void {
    if (!ensureValid(this.form)) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.register(this.form.getRawValue()).subscribe({
      next: (r) => this.done.set(r.message),
      error: (err) => {
        this.busy.set(false);
        this.error.set(apiErrorMessage(err));
      },
    });
  }
}
