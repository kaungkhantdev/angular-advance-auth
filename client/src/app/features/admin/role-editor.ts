import { Component, computed, inject, input, OnInit, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { forkJoin, of } from 'rxjs';
import { RolesApi } from '../../core/api/admin.api';
import type { PermissionGroup, PermissionInfo, Role } from '../../core/api/api.models';
import { AuthService } from '../../core/auth/auth.service';
import type { Permission } from '../../core/auth/permissions';
import { ensureValid } from '../../core/forms';
import { apiErrorMessage } from '../../core/http/errors';

const COARSE = ['read', 'write'] as const;

/**
 * Create/view/edit a role. Everything here is driven by the server's permission
 * catalog: resources, their Read/Write permissions, fine-grained actions and what
 * each permission implies. Nothing about permissions is hard-coded in the client.
 */
@Component({
  selector: 'app-role-editor',
  imports: [ReactiveFormsModule, RouterLink],
  template: `
    <p><a routerLink="/admin/roles" class="small">← All roles</a></p>
    @if (error()) { <div class="alert alert-error" role="alert">{{ error() }}</div> }

    <form [formGroup]="form" (ngSubmit)="save()" class="stack">
      <div class="page-header spread">
        <div>
          <h1>{{ id() ? form.getRawValue().name || 'Role' : 'New role' }}</h1>
          @if (role()?.isSystem) {
            <p class="muted">System role — defined on the server and read-only here.</p>
          } @else if (!editable()) {
            <p class="muted">You have read-only access to roles.</p>
          }
        </div>
        @if (editable()) {
          <div class="row">
            @if (id() && canDelete()) { <button type="button" class="btn btn-danger" (click)="remove()" [disabled]="busy()">Delete</button> }
            <button class="btn btn-primary" [disabled]="busy()">Save role</button>
          </div>
        }
      </div>

      <section class="card grid">
        <div class="field">
          <label for="name">Name</label>
          <input id="name" type="text" formControlName="name" placeholder="e.g. support-agent" />
          <span class="hint">Lowercase letters, digits, "_" and "-"</span>
        </div>
        <div class="field">
          <label for="desc">Description</label>
          <input id="desc" type="text" formControlName="description" />
        </div>
      </section>

      <section class="card">
        <div class="spread">
          <h2 style="margin: 0">Access</h2>
          <span class="badge badge-primary">{{ effectiveCount() }} effective permissions</span>
        </div>
        <p class="small muted">
          <strong>Write</strong> includes read and every create/update/delete action of the resource.
          @if (editable()) { Permissions you don't hold yourself can't be delegated and are greyed out. }
        </p>

        <div class="table-wrap">
          <table class="matrix">
            <thead>
              <tr><th>Resource</th>@for (a of coarse; track a) { <th class="c">{{ a }}</th> }<th></th></tr>
            </thead>
            <tbody>
              @for (g of catalog(); track g.resource) {
                <tr>
                  <td><strong>{{ g.label }}</strong></td>
                  @for (a of coarse; track a) {
                    <td class="c">
                      @if (find(g, a); as p) {
                        <input type="checkbox" [attr.aria-label]="g.label + ' ' + a"
                               [checked]="isOn(p.name)" [disabled]="!canToggle(p.name)"
                               [title]="hint(p)" (change)="toggle(p.name)" />
                      } @else { <span class="muted">—</span> }
                    </td>
                  }
                  <td class="c">
                    @if (advanced(g).length) {
                      <button type="button" class="btn btn-ghost btn-sm" (click)="toggleExpanded(g.resource)" [attr.aria-expanded]="expanded().has(g.resource)">
                        {{ expanded().has(g.resource) ? 'Hide' : 'Advanced' }}
                        @if (advancedDirectCount(g); as n) { <span class="badge">{{ n }}</span> }
                      </button>
                    }
                  </td>
                </tr>
                @if (expanded().has(g.resource)) {
                  <tr class="advanced">
                    <td colspan="4">
                      <div class="adv-grid">
                        @for (p of advanced(g); track p.name) {
                          <label class="checkbox" [class.disabled]="!canToggle(p.name)" [title]="hint(p)">
                            <input type="checkbox" [checked]="isOn(p.name)" [disabled]="!canToggle(p.name)" (change)="toggle(p.name)" />
                            <span>
                              <code>{{ p.action }}</code>
                              @if (impliedBy().get(p.name); as via) { <span class="badge">via {{ via }}</span> }
                              <br /><span class="small muted">{{ p.description }}</span>
                            </span>
                          </label>
                        }
                      </div>
                    </td>
                  </tr>
                }
              }
            </tbody>
          </table>
        </div>
      </section>
    </form>
  `,
  styles: `
    .matrix th.c, .matrix td.c { text-align: center; width: 6.5rem; }
    .matrix th { text-transform: capitalize; }
    .matrix input[type='checkbox'] { width: 1.05rem; height: 1.05rem; accent-color: var(--primary); cursor: pointer; }
    .matrix input:disabled { cursor: not-allowed; }
    tr.advanced td { background: var(--surface-2); }
    .adv-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: .6rem 1rem; padding: .25rem 0; }
    .checkbox.disabled { opacity: .6; cursor: not-allowed; }
  `,
})
export class RoleEditor implements OnInit {
  readonly id = input<string>();

  private readonly api = inject(RolesApi);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly coarse = COARSE;
  protected readonly form = inject(NonNullableFormBuilder).group({
    name: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50), Validators.pattern(/^[a-z][a-z0-9_-]*$/)]],
    description: ['', Validators.maxLength(300)],
  });
  protected readonly role = signal<Role | null>(null);
  protected readonly catalog = signal<PermissionGroup[]>([]);
  /** Directly assigned permissions — what gets saved. */
  protected readonly selected = signal(new Set<Permission>());
  protected readonly expanded = signal(new Set<string>());
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly editable = computed(() => {
    if (this.role()?.isSystem) return false;
    return this.id() ? this.auth.hasPermission('roles:update') : this.auth.hasPermission('roles:create');
  });
  protected readonly canDelete = computed(() => this.auth.hasPermission('roles:delete'));

  private readonly byName = computed(() => {
    const map = new Map<Permission, PermissionInfo>();
    for (const g of this.catalog()) for (const p of g.permissions) map.set(p.name, p);
    return map;
  });

  /** For each permission granted indirectly, the selected permission that grants it. */
  protected readonly impliedBy = computed(() => {
    const via = new Map<Permission, Permission>();
    for (const s of this.selected()) {
      for (const g of this.byName().get(s)?.grants ?? []) if (!this.selected().has(g) && !via.has(g)) via.set(g, s);
    }
    return via;
  });

  protected readonly effectiveCount = computed(() => new Set([...this.selected(), ...this.impliedBy().keys()]).size);

  ngOnInit(): void {
    const id = this.id();
    forkJoin({ catalog: this.api.permissions(), role: id ? this.api.get(id) : of(null) }).subscribe({
      next: ({ catalog, role }) => {
        this.catalog.set(catalog);
        if (role) {
          this.role.set(role);
          this.form.setValue({ name: role.name, description: role.description });
          this.selected.set(new Set(role.permissions));
          // Open resources whose fine-grained permissions are in use, so nothing is hidden.
          this.expanded.set(new Set(catalog.filter((g) => this.advancedDirectCount(g) > 0).map((g) => g.resource)));
        }
        if (!this.editable()) this.form.disable();
      },
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
  }

  protected find(g: PermissionGroup, action: string): PermissionInfo | undefined {
    return g.permissions.find((p) => p.action === action);
  }

  protected advanced(g: PermissionGroup): PermissionInfo[] {
    return g.permissions.filter((p) => !(COARSE as readonly string[]).includes(p.action));
  }

  protected advancedDirectCount(g: PermissionGroup): number {
    return this.advanced(g).filter((p) => this.selected().has(p.name)).length;
  }

  protected isOn(p: Permission): boolean {
    return this.selected().has(p) || this.impliedBy().has(p);
  }

  /** Implied permissions are locked on; untick the granting permission to remove them. */
  protected canToggle(p: Permission): boolean {
    return this.editable() && !this.impliedBy().has(p) && this.auth.hasPermission(p);
  }

  protected hint(p: PermissionInfo): string {
    const via = this.impliedBy().get(p.name);
    if (via) return `Included via ${via}`;
    if (this.editable() && !this.auth.hasPermission(p.name)) return "You don't hold this permission, so you can't delegate it";
    return p.grants.length ? `${p.description}. Also grants: ${p.grants.join(', ')}` : p.description;
  }

  protected toggle(p: Permission): void {
    this.selected.update((s) => {
      const next = new Set(s);
      if (!next.delete(p)) next.add(p);
      return next;
    });
  }

  protected toggleExpanded(resource: string): void {
    this.expanded.update((s) => {
      const next = new Set(s);
      if (!next.delete(resource)) next.add(resource);
      return next;
    });
  }

  protected save(): void {
    if (!ensureValid(this.form)) return;
    // Drop permissions already granted by another selected one, so the stored role stays minimal.
    const permissions = [...this.selected()].filter((p) => !this.isRedundant(p));
    const body = { ...this.form.getRawValue(), permissions };
    const id = this.id();
    this.busy.set(true);
    this.error.set(null);
    (id ? this.api.update(id, body) : this.api.create(body)).subscribe({
      next: () => void this.router.navigate(['/admin/roles']),
      error: (e) => { this.busy.set(false); this.error.set(apiErrorMessage(e)); },
    });
  }

  protected remove(): void {
    const id = this.id();
    if (!id || !confirm('Delete this role?')) return;
    this.busy.set(true);
    this.api.delete(id).subscribe({
      next: () => void this.router.navigate(['/admin/roles']),
      error: (e) => { this.busy.set(false); this.error.set(apiErrorMessage(e)); },
    });
  }

  /** True if another selected permission already grants `p`. */
  private isRedundant(p: Permission): boolean {
    return [...this.selected()].some((s) => s !== p && (this.byName().get(s)?.grants ?? []).includes(p));
  }
}
