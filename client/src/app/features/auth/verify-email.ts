import { Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AccountApi } from '../../core/api/account.api';
import { apiErrorMessage } from '../../core/http/errors';

@Component({
  selector: 'app-verify-email',
  imports: [RouterLink],
  template: `
    <div class="auth-page">
      <div class="card auth-card stack">
        <div class="brand"><span class="brand-mark">A</span> Advance Auth</div>
        <h1>E-mail verification</h1>
        @switch (state()) {
          @case ('pending') { <p class="muted">Verifying…</p> }
          @case ('ok') { <div class="alert alert-success">{{ message() }}</div> }
          @case ('error') { <div class="alert alert-error">{{ message() }}</div> }
        }
        <a routerLink="/login" class="btn btn-primary btn-block">Go to sign in</a>
      </div>
    </div>
  `,
})
export class VerifyEmail implements OnInit {
  private readonly api = inject(AccountApi);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  protected readonly state = signal<'pending' | 'ok' | 'error'>('pending');
  protected readonly message = signal('');

  ngOnInit(): void {
    const token = this.route.snapshot.queryParamMap.get('token');
    // Strip the token from the address bar/history so it doesn't linger or leak via Referer.
    void this.router.navigate([], { queryParams: {}, replaceUrl: true });
    if (!token) {
      this.state.set('error');
      this.message.set('Verification link is missing its token.');
      return;
    }
    this.api.verifyEmail(token).subscribe({
      next: (r) => { this.state.set('ok'); this.message.set(r.message); },
      error: (err) => { this.state.set('error'); this.message.set(apiErrorMessage(err)); },
    });
  }
}
