import { Component, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AccountApi } from '../../core/api/account.api';
import { apiErrorMessage } from '../../core/http/errors';
import { ensureValid } from '../../core/forms';

@Component({
  selector: 'app-forgot-password',
  imports: [ReactiveFormsModule, RouterLink],
  template: `
    <div class="auth-page">
      <div class="card auth-card">
        <div class="brand"><span class="brand-mark">A</span> Advance Auth</div>
        <h1>Reset password</h1>
        @if (done()) {
          <div class="alert alert-success">{{ done() }}</div>
        } @else {
          <p class="muted">Enter your e-mail and we'll send you a link to choose a new password.</p>
          <form [formGroup]="form" (ngSubmit)="submit()" class="stack" novalidate>
            @if (error()) { <div class="alert alert-error">{{ error() }}</div> }
            <div class="field">
              <label for="email">E-mail</label>
              <input id="email" type="email" formControlName="email" autocomplete="email" autofocus />
            </div>
            <button class="btn btn-primary btn-block" [disabled]="busy()">Send reset link</button>
          </form>
        }
        <p class="footer"><a routerLink="/login">Back to sign in</a></p>
      </div>
    </div>
  `,
})
export class ForgotPassword {
  private readonly api = inject(AccountApi);
  protected readonly form = inject(NonNullableFormBuilder).group({ email: ['', [Validators.required, Validators.email]] });
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly done = signal<string | null>(null);

  protected submit(): void {
    if (!ensureValid(this.form)) return;
    this.busy.set(true);
    this.api.forgotPassword(this.form.getRawValue().email).subscribe({
      next: (r) => this.done.set(r.message),
      error: (err) => { this.busy.set(false); this.error.set(apiErrorMessage(err)); },
    });
  }
}
