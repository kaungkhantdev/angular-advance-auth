import { Component, inject, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import type { Observable } from 'rxjs';
import { AccountApi } from '../../core/api/account.api';
import type { MfaSetup } from '../../core/api/api.models';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../core/http/errors';
import { ensureValid } from '../../core/forms';

type Step = 'idle' | 'confirm-password' | 'scan' | 'codes' | 'disable' | 'regenerate';

/** TOTP enrolment wizard: re-auth → scan QR → verify code → save recovery codes. */
@Component({
  selector: 'app-mfa-settings',
  imports: [ReactiveFormsModule],
  template: `
    <section class="card stack">
      <div class="spread">
        <div>
          <h2>Two-factor authentication</h2>
          <p class="muted small" style="margin: 0">Require a code from an authenticator app (Google Authenticator, 1Password, Authy…) when signing in.</p>
        </div>
        @if (auth.user()?.mfaEnabled) { <span class="badge badge-success">Enabled</span> }
        @else { <span class="badge badge-warning">Disabled</span> }
      </div>

      @if (error()) { <div class="alert alert-error">{{ error() }}</div> }

      @switch (step()) {
        @case ('idle') {
          <div class="row">
            @if (auth.user()?.mfaEnabled) {
              <button class="btn" (click)="go('regenerate')">New recovery codes</button>
              <button class="btn btn-danger" (click)="go('disable')">Disable 2FA</button>
            } @else {
              <button class="btn btn-primary" (click)="go('confirm-password')">Enable 2FA</button>
            }
          </div>
        }

        @case ('confirm-password') {
          <form [formGroup]="pwForm" (ngSubmit)="start()" class="stack" style="max-width: 420px">
            <div class="field">
              <label for="mfa-pw">Confirm your password to continue</label>
              <input id="mfa-pw" type="password" formControlName="password" autocomplete="current-password" autofocus />
            </div>
            <div class="row">
              <button class="btn btn-primary" [disabled]="busy()">Continue</button>
              <button type="button" class="btn btn-ghost" (click)="cancel()">Cancel</button>
            </div>
          </form>
        }

        @case ('scan') {
          @if (setup(); as s) {
            <div class="scan">
              <img [src]="s.qrCodeDataUrl" alt="QR code for authenticator app" width="180" height="180" />
              <div class="stack-sm">
                <p><strong>1.</strong> Scan this QR code with your authenticator app.</p>
                <p class="small muted">Can't scan? Enter this key manually:<br /><code class="secret">{{ s.secret }}</code></p>
                <form [formGroup]="codeForm" (ngSubmit)="confirm()" class="stack-sm">
                  <label for="totp"><strong>2.</strong> Enter the 6-digit code it shows:</label>
                  <div class="row">
                    <input id="totp" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" formControlName="code" style="max-width: 9rem" />
                    <button class="btn btn-primary" [disabled]="busy()">Verify & enable</button>
                    <button type="button" class="btn btn-ghost" (click)="cancel()">Cancel</button>
                  </div>
                </form>
              </div>
            </div>
          }
        }

        @case ('codes') {
          <div class="alert alert-warning">
            Save these recovery codes somewhere safe. Each can be used once if you lose your device.
            They won't be shown again.
          </div>
          <div class="codes">@for (c of recoveryCodes(); track c) { <span>{{ c }}</span> }</div>
          <div class="row">
            <button class="btn" (click)="copyCodes()">{{ copied() ? 'Copied ✓' : 'Copy' }}</button>
            <button class="btn btn-primary" (click)="cancel()">I've saved them</button>
          </div>
        }

        @case ('disable') {
          <form [formGroup]="disableForm" (ngSubmit)="disable()" class="stack" style="max-width: 420px">
            <div class="field">
              <label for="d-pw">Password</label>
              <input id="d-pw" type="password" formControlName="password" autocomplete="current-password" />
            </div>
            <div class="field">
              <label for="d-code">Authentication or recovery code</label>
              <input id="d-code" type="text" formControlName="code" autocomplete="one-time-code" />
            </div>
            <div class="row">
              <button class="btn btn-danger" [disabled]="busy()">Disable 2FA</button>
              <button type="button" class="btn btn-ghost" (click)="cancel()">Cancel</button>
            </div>
          </form>
        }

        @case ('regenerate') {
          <form [formGroup]="pwForm" (ngSubmit)="regenerate()" class="stack" style="max-width: 420px">
            <p class="small muted" style="margin: 0">This invalidates all of your existing recovery codes.</p>
            <div class="field">
              <label for="r-pw">Confirm your password</label>
              <input id="r-pw" type="password" formControlName="password" autocomplete="current-password" />
            </div>
            <div class="row">
              <button class="btn btn-primary" [disabled]="busy()">Generate new codes</button>
              <button type="button" class="btn btn-ghost" (click)="cancel()">Cancel</button>
            </div>
          </form>
        }
      }
    </section>
  `,
  styles: `
    .scan { display: flex; gap: 1.5rem; align-items: flex-start; flex-wrap: wrap; }
    .scan img { border-radius: 8px; background: #fff; padding: 6px; }
    .secret { word-break: break-all; }
  `,
})
export class MfaSettings {
  protected readonly auth = inject(AuthService);
  private readonly api = inject(AccountApi);
  private readonly fb = inject(NonNullableFormBuilder);

  protected readonly step = signal<Step>('idle');
  protected readonly setup = signal<MfaSetup | null>(null);
  protected readonly recoveryCodes = signal<string[]>([]);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly copied = signal(false);

  protected readonly pwForm = this.fb.group({ password: ['', Validators.required] });
  protected readonly codeForm = this.fb.group({ code: ['', [Validators.required, Validators.pattern(/^\d{6}$/)]] });
  protected readonly disableForm = this.fb.group({ password: ['', Validators.required], code: ['', [Validators.required, Validators.minLength(6)]] });

  protected go(step: Step): void {
    this.error.set(null);
    this.step.set(step);
  }

  protected cancel(): void {
    this.pwForm.reset();
    this.codeForm.reset();
    this.disableForm.reset();
    this.setup.set(null);
    this.recoveryCodes.set([]);
    this.copied.set(false);
    this.go('idle');
  }

  protected start(): void {
    if (!ensureValid(this.pwForm)) return;
    this.run(this.api.startMfaSetup(this.pwForm.getRawValue().password), (s) => {
      this.pwForm.reset();
      this.setup.set(s);
      this.step.set('scan');
    });
  }

  protected confirm(): void {
    if (!ensureValid(this.codeForm)) return;
    this.run(this.api.enableMfa(this.codeForm.getRawValue().code), (r) => {
      this.recoveryCodes.set(r.recoveryCodes);
      this.setup.set(null);
      this.step.set('codes');
      void this.auth.reloadUser();
    });
  }

  protected disable(): void {
    if (!ensureValid(this.disableForm)) return;
    const { password, code } = this.disableForm.getRawValue();
    this.run(this.api.disableMfa(password, code), () => {
      void this.auth.reloadUser();
      this.cancel();
    });
  }

  protected regenerate(): void {
    if (!ensureValid(this.pwForm)) return;
    this.run(this.api.regenerateRecoveryCodes(this.pwForm.getRawValue().password), (r) => {
      this.pwForm.reset();
      this.recoveryCodes.set(r.recoveryCodes);
      this.step.set('codes');
    });
  }

  protected async copyCodes(): Promise<void> {
    await navigator.clipboard.writeText(this.recoveryCodes().join('\n'));
    this.copied.set(true);
  }

  private run<T>(obs: Observable<T>, onSuccess: (value: T) => void): void {
    this.busy.set(true);
    this.error.set(null);
    obs.subscribe({
      next: (v) => { this.busy.set(false); onSuccess(v); },
      error: (err) => { this.busy.set(false); this.error.set(apiErrorMessage(err)); },
    });
  }
}
