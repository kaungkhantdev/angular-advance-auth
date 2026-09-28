import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-forbidden',
  imports: [RouterLink],
  template: `
    <div class="card" style="max-width: 520px; margin: 3rem auto; text-align: center">
      <h1>403 — Access denied</h1>
      <p class="muted">Your role doesn't include permission for this page. Ask an administrator if you think this is a mistake.</p>
      <a routerLink="/" class="btn btn-primary">Back to dashboard</a>
    </div>
  `,
})
export class Forbidden {}

@Component({
  selector: 'app-not-found',
  imports: [RouterLink],
  template: `
    <div class="card" style="max-width: 520px; margin: 3rem auto; text-align: center">
      <h1>404 — Page not found</h1>
      <p class="muted">The page you're looking for doesn't exist.</p>
      <a routerLink="/" class="btn btn-primary">Go home</a>
    </div>
  `,
})
export class NotFound {}
