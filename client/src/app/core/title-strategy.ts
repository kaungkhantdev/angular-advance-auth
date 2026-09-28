import { inject, Service } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { type RouterStateSnapshot, TitleStrategy } from '@angular/router';

@Service({ autoProvided: false })
export class AppTitleStrategy extends TitleStrategy {
  private readonly title = inject(Title);

  override updateTitle(snapshot: RouterStateSnapshot): void {
    const page = this.buildTitle(snapshot);
    this.title.setTitle(page ? `${page} · Advance Auth` : 'Advance Auth');
  }
}
