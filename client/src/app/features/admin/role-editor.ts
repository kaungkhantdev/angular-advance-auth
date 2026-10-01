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

/**
 * Create/view/edit a role. The checklist is driven by the server's permission
 * catalog, grouped by resource. Nothing about permissions is hard-coded in the client.
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
          @if (role()?.locked) {
            <p class="muted">Super admin always has every permission and can't be edited.</p>
          } @else if (!editable()) {
            <p class="muted">You have read-only access to roles.</p>
          }
        </div>
        @if (editable()) {
          <div class="row">
            @if (id() && canDelete() && !role()?.isSystem) { <button type="button" class="btn btn-danger" (click)="remove()" [disabled]="busy()">Delete</button> }
            <button class="btn btn-primary" [disabled]="busy()">Save role</button>
          </div>
        }
      </div>

      <section class="card grid">
        <div class="field">
          <label for="name">Name</label>
          <input id="name" type="text" formControlName="name" placeholder="e.g. support-agent" />
          @if (role()?.isSystem) {
            <span class="hint">System role names are fixed</span>
          } @else {
            <span class="hint">Lowercase letters, digits, "_" and "-"</span>
          }
        </div>
        <div class="field">
          <label for="desc">Description</label>
          <input id="desc" type="text" formControlName="description" />
        </div>
      </section>

      <section class="card">
        <div class="spread">
          <h2 style="margin: 0">Permissions</h2>
          <span class="badge badge-primary">{{ selected().size }} selected</span>
        </div>
        <p class="small muted">
          A role grants exactly the permissions ticked here.
          @if (editable()) { Permissions you don't hold yourself can't be delegated and are greyed out. }
        </p>

        @for (g of catalog(); track g.resource) {
          <fieldset class="group">
            <legend>{{ g.label }}</legend>
            <div class="perm-grid">
              @for (p of g.permissions; track p.name) {
                <label class="checkbox" [class.disabled]="!canToggle(p.name)" [title]="hint(p)">
                  <input type="checkbox" [checked]="selected().has(p.name)" [disabled]="!canToggle(p.name)" (change)="toggle(p.name)" />
                  <span><code>{{ p.action }}</code><br /><span class="small muted">{{ p.description }}</span></span>
                </label>
              }
            </div>
          </fieldset>
        }
      </section>
    </form>
  `,
  styles: `
    .group { border: 0; border-top: 1px solid var(--border); margin: 0; padding: .75rem 0 .25rem; }
    .group legend { font-weight: 600; padding-right: .5rem; }
    .perm-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: .6rem 1rem; }
    .checkbox input { accent-color: var(--primary); }
    .checkbox.disabled { opacity: .6; cursor: not-allowed; }
  `,
})
export class RoleEditor implements OnInit {
  readonly id = input<string>();

  private readonly api = inject(RolesApi);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly form = inject(NonNullableFormBuilder).group({
    name: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50), Validators.pattern(/^[a-z][a-z0-9_-]*$/)]],
    description: ['', Validators.maxLength(300)],
  });
  protected readonly role = signal<Role | null>(null);
  protected readonly catalog = signal<PermissionGroup[]>([]);
  protected readonly selected = signal(new Set<Permission>());
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly editable = computed(() => {
    if (this.role()?.locked) return false;
    return this.id() ? this.auth.hasPermission('roles:update') : this.auth.hasPermission('roles:create');
  });
  protected readonly canDelete = computed(() => this.auth.hasPermission('roles:delete'));

  ngOnInit(): void {
    const id = this.id();
    forkJoin({ catalog: this.api.permissions(), role: id ? this.api.get(id) : of(null) }).subscribe({
      next: ({ catalog, role }) => {
        this.catalog.set(catalog);
        if (role) {
          this.role.set(role);
          this.form.setValue({ name: role.name, description: role.description });
          this.selected.set(new Set(role.permissions));
        }
        if (!this.editable()) this.form.disable();
        else if (role?.isSystem) this.form.controls.name.disable();
      },
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
  }

  protected canToggle(p: Permission): boolean {
    return this.editable() && this.auth.hasPermission(p);
  }

  protected hint(p: PermissionInfo): string {
    if (this.editable() && !this.auth.hasPermission(p.name)) return "You don't hold this permission, so you can't delegate it";
    return p.description;
  }

  protected toggle(p: Permission): void {
    this.selected.update((s) => {
      const next = new Set(s);
      if (!next.delete(p)) next.add(p);
      return next;
    });
  }

  protected save(): void {
    if (!ensureValid(this.form)) return;
    const permissions = [...this.selected()];
    const { name, description } = this.form.getRawValue();
    const body = { name, description, permissions };
    const id = this.id();
    this.busy.set(true);
    this.error.set(null);
    // System role names are fixed, so don't send one.
    const update = this.role()?.isSystem ? { description, permissions } : body;
    (id ? this.api.update(id, update) : this.api.create(body)).subscribe({
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
}
