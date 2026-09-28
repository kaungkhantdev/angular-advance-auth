import type { AbstractControl } from '@angular/forms';

/**
 * Submit buttons stay enabled (disabled buttons block Enter-to-submit and hide
 * *why* a form can't be sent); instead, validate on submit and reveal errors.
 */
export function ensureValid(form: AbstractControl): boolean {
  if (form.valid) return true;
  form.markAllAsTouched();
  return false;
}
