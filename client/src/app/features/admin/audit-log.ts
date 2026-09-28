import { DatePipe, JsonPipe } from '@angular/common';
import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AuditApi } from '../../core/api/admin.api';
import type { AuditEntry } from '../../core/api/api.models';
import { apiErrorMessage } from '../../core/http/errors';

const PAGE = 50;
const FILTERS = [
  { label: 'All events', value: '' },
  { label: 'Authentication', value: 'auth.' },
  { label: 'Failed sign-ins', value: 'auth.login_failed' },
  { label: 'User management', value: 'users.' },
  { label: 'Role changes', value: 'roles.' },
  { label: 'Sessions', value: 'sessions.' },
  { label: 'Articles', value: 'articles.' },
];

@Component({
  selector: 'app-audit-log',
  imports: [DatePipe, JsonPipe, FormsModule],
  template: `
    <div class="page-header spread">
      <div>
        <h1>Security audit log</h1>
        <p class="muted">Append-only record of authentication and authorization events.</p>
      </div>
      <select [(ngModel)]="action" (ngModelChange)="reload()" aria-label="Filter events" style="max-width: 14rem">
        @for (f of filters; track f.value) { <option [value]="f.value">{{ f.label }}</option> }
      </select>
    </div>
    @if (error()) { <div class="alert alert-error">{{ error() }}</div> }

    <div class="card table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th class="hide-sm">Target</th><th class="hide-sm">IP</th></tr></thead>
        <tbody>
          @for (e of entries(); track e.id) {
            <tr>
              <td class="small" style="white-space: nowrap">{{ e.at | date: 'MMM d, HH:mm:ss' }}</td>
              <td>
                <code [class.fail]="!e.success">{{ e.action }}</code>
                @if (e.metadata) { <div class="small muted meta">{{ e.metadata | json }}</div> }
              </td>
              <td class="small">{{ e.actorEmail ?? (e.actorId ? 'deleted user' : '—') }}</td>
              <td class="hide-sm small muted">{{ e.targetType ?? '' }}</td>
              <td class="hide-sm small mono">{{ e.ip ?? '—' }}</td>
            </tr>
          } @empty { <tr><td colspan="5" class="muted">No events.</td></tr> }
        </tbody>
      </table>
      @if (entries().length < total()) {
        <div style="margin-top: 1rem; text-align: center"><button class="btn btn-sm" (click)="more()">Load more</button></div>
      }
    </div>
  `,
  styles: `
    code.fail { color: var(--danger); }
    .meta { max-width: 32rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); font-size: .75rem; }
  `,
})
export class AuditLog implements OnInit {
  private readonly api = inject(AuditApi);
  protected readonly filters = FILTERS;
  protected action = '';
  protected readonly entries = signal<AuditEntry[]>([]);
  protected readonly total = signal(0);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.reload();
  }

  protected reload(): void {
    this.entries.set([]);
    this.fetch(0);
  }

  protected more(): void {
    this.fetch(this.entries().length);
  }

  private fetch(offset: number): void {
    this.api.list({ limit: PAGE, offset, action: this.action || undefined }).subscribe({
      next: (p) => { this.entries.update((e) => [...e, ...p.items]); this.total.set(p.total); },
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
  }
}
