import { HttpClient } from '@angular/common/http';
import { inject, Service } from '@angular/core';
import type { Message, MfaSetup, Session } from './api.models';

/** Public account flows and the signed-in user's self-service endpoints. */
@Service()
export class AccountApi {
  private readonly http = inject(HttpClient);

  register(body: { email: string; name: string; password: string }) {
    return this.http.post<Message>('/api/auth/register', body);
  }
  verifyEmail(token: string) {
    return this.http.post<Message>('/api/auth/verify-email', { token });
  }
  resendVerification(email: string) {
    return this.http.post<Message>('/api/auth/resend-verification', { email });
  }
  forgotPassword(email: string) {
    return this.http.post<Message>('/api/auth/forgot-password', { email });
  }
  resetPassword(token: string, password: string) {
    return this.http.post<Message>('/api/auth/reset-password', { token, password });
  }

  changePassword(currentPassword: string, newPassword: string) {
    return this.http.post<Message>('/api/auth/change-password', { currentPassword, newPassword });
  }
  sessions() {
    return this.http.get<Session[]>('/api/auth/sessions');
  }
  revokeSession(id: string) {
    return this.http.delete<void>(`/api/auth/sessions/${encodeURIComponent(id)}`);
  }

  startMfaSetup(password: string) {
    return this.http.post<MfaSetup>('/api/auth/mfa/setup', { password });
  }
  enableMfa(code: string) {
    return this.http.post<{ recoveryCodes: string[] }>('/api/auth/mfa/enable', { code });
  }
  disableMfa(password: string, code: string) {
    return this.http.post<void>('/api/auth/mfa/disable', { password, code });
  }
  regenerateRecoveryCodes(password: string) {
    return this.http.post<{ recoveryCodes: string[] }>('/api/auth/mfa/recovery-codes', { password });
  }
}
