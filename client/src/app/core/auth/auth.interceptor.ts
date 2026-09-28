import { HttpErrorResponse, type HttpInterceptorFn, type HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { apiErrorCode } from '../http/errors';
import { AuthService, SKIP_AUTH_REFRESH } from './auth.service';

const withToken = (req: HttpRequest<unknown>, token: string | null) =>
  token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req;

/**
 * - Attaches the in-memory access token to our own API calls only (never to
 *   third-party URLs — that would leak the token).
 * - Sends cookies on /api/auth calls so the refresh cookie works cross-origin too.
 * - On an expired/invalid access token, refreshes once and replays the request.
 * - On a server-side revoked session, signs the user out.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith('/api/')) return next(req);

  const auth = inject(AuthService);
  const outgoing = req.url.startsWith('/api/auth/') ? req.clone({ withCredentials: true }) : req;

  if (outgoing.context.get(SKIP_AUTH_REFRESH)) return next(outgoing);

  return next(withToken(outgoing, auth.getAccessToken())).pipe(
    catchError((err: unknown) => {
      if (!(err instanceof HttpErrorResponse) || err.status !== 401) return throwError(() => err);

      const code = apiErrorCode(err);
      if (code === 'TOKEN_EXPIRED' || code === 'INVALID_TOKEN' || code === 'UNAUTHENTICATED') {
        return auth.refresh().pipe(
          switchMap((token) => next(withToken(outgoing, token))),
          catchError((refreshErr: unknown) => {
            auth.endSession('expired');
            return throwError(() => refreshErr);
          }),
        );
      }
      if (code === 'SESSION_REVOKED') auth.endSession('revoked');
      return throwError(() => err);
    }),
  );
};
