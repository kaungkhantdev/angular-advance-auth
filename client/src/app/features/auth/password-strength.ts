import { Component, computed, input } from '@angular/core';

/**
 * Lightweight strength hint. Mirrors the server policy (length-first, NIST 800-63B);
 * the server remains the authority and rejects anything that doesn't pass.
 */
@Component({
  selector: 'app-password-strength',
  template: `
    <div class="meter" [attr.data-level]="level()"><span></span><span></span><span></span><span></span></div>
    <span class="hint">{{ label() }}</span>
  `,
  styles: `
    :host { display: flex; align-items: center; gap: .6rem; }
    .meter { display: flex; gap: 3px; flex: 1; }
    .meter span { height: 4px; flex: 1; border-radius: 2px; background: var(--border); }
    .meter[data-level='1'] span:nth-child(-n + 1) { background: var(--danger); }
    .meter[data-level='2'] span:nth-child(-n + 2) { background: var(--warning); }
    .meter[data-level='3'] span:nth-child(-n + 3) { background: var(--success); }
    .meter[data-level='4'] span { background: var(--success); }
    .hint { font-size: .8rem; color: var(--muted); min-width: 7rem; text-align: right; }
  `,
})
export class PasswordStrength {
  readonly password = input('');

  protected readonly level = computed(() => {
    const p = this.password();
    if (!p) return 0;
    if (p.length < 12) return 1;
    const variety = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
    if (p.length >= 20 || (p.length >= 16 && variety >= 3)) return 4;
    return variety >= 3 ? 3 : 2;
  });

  protected readonly label = computed(() =>
    ['', 'Too short (min 12)', 'Okay', 'Strong', 'Very strong'][this.level()],
  );
}
