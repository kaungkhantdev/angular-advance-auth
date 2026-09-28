import { Directive, effect, inject, input, TemplateRef, ViewContainerRef } from '@angular/core';
import { AuthService } from './auth.service';
import type { Permission } from './permissions';

/**
 * Structural directive that renders its template only if the user holds the
 * permission(s). Reacts to permission changes (e.g. after a role update).
 *
 *   <button *hasPermission="'users:create'">New user</button>
 *   <a *hasPermission="['users:read', 'roles:read']; mode: 'any'; else noAccess">Admin</a>
 */
@Directive({ selector: '[hasPermission]' })
export class HasPermissionDirective {
  private readonly auth = inject(AuthService);
  private readonly template = inject(TemplateRef<unknown>);
  private readonly container = inject(ViewContainerRef);

  readonly hasPermission = input.required<Permission | Permission[]>();
  readonly hasPermissionMode = input<'all' | 'any'>('all');
  readonly hasPermissionElse = input<TemplateRef<unknown> | null>(null);

  private rendered: 'main' | 'else' | null = null;

  constructor() {
    effect(() => {
      const required = ([] as Permission[]).concat(this.hasPermission());
      const allowed = this.hasPermissionMode() === 'any'
        ? this.auth.hasAnyPermission(...required)
        : this.auth.hasPermission(...required);
      const elseTpl = this.hasPermissionElse();
      const next = allowed ? 'main' : elseTpl ? 'else' : null;
      if (next === this.rendered) return;

      this.container.clear();
      if (next === 'main') this.container.createEmbeddedView(this.template);
      if (next === 'else') this.container.createEmbeddedView(elseTpl!);
      this.rendered = next;
    });
  }
}
