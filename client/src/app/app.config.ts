import { provideHttpClient, withFetch, withInterceptors } from '@angular/common/http';
import {
  ApplicationConfig, inject, provideAppInitializer, provideBrowserGlobalErrorListeners,
} from '@angular/core';
import { provideRouter, TitleStrategy, withComponentInputBinding } from '@angular/router';
import { routes } from './app.routes';
import { authInterceptor } from './core/auth/auth.interceptor';
import { AuthService } from './core/auth/auth.service';
import { AppTitleStrategy } from './core/title-strategy';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideHttpClient(withFetch(), withInterceptors([authInterceptor])),
    provideRouter(routes, withComponentInputBinding()),
    { provide: TitleStrategy, useClass: AppTitleStrategy },
    // Resume the session from the HttpOnly refresh cookie before the first route resolves,
    // so guards see the real auth state on a hard reload.
    provideAppInitializer(() => inject(AuthService).restoreSession()),
  ],
};
