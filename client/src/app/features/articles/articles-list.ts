import { DatePipe } from '@angular/common';
import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ArticlesApi } from '../../core/api/articles.api';
import type { Article } from '../../core/api/api.models';
import { AuthService } from '../../core/auth/auth.service';
import { HasPermissionDirective } from '../../core/auth/has-permission.directive';
import { apiErrorMessage } from '../../core/http/errors';

@Component({
  selector: 'app-articles-list',
  imports: [RouterLink, DatePipe, HasPermissionDirective],
  template: `
    <div class="page-header spread">
      <div>
        <h1>Articles</h1>
        <p class="muted">
          Demonstrates RBAC combined with ownership: authors edit their own drafts,
          editors edit and publish anything, only admins delete others' work.
        </p>
      </div>
      <a *hasPermission="'articles:create'" routerLink="/articles/new" class="btn btn-primary">New article</a>
    </div>

    @if (error()) { <div class="alert alert-error">{{ error() }}</div> }

    <div class="stack">
      @for (a of articles(); track a.id) {
        <article class="card">
          <div class="spread">
            <div>
              <h2 style="margin: 0"><a [routerLink]="['/articles', a.id]">{{ a.title }}</a></h2>
              <p class="small muted" style="margin: .25rem 0 0">
                by {{ a.authorId === auth.user()?.id ? 'you' : a.authorName }} · updated {{ a.updatedAt | date: 'medium' }}
              </p>
            </div>
            <div class="row">
              @if (a.status === 'published') { <span class="badge badge-success">Published</span> }
              @else { <span class="badge badge-warning">Draft</span> }
              @if (a.can.publish) {
                <button class="btn btn-sm" (click)="togglePublish(a)">{{ a.status === 'published' ? 'Unpublish' : 'Publish' }}</button>
              }
              @if (a.can.update) { <a class="btn btn-sm" [routerLink]="['/articles', a.id, 'edit']">Edit</a> }
              @if (a.can.delete) { <button class="btn btn-sm btn-danger" (click)="remove(a)">Delete</button> }
            </div>
          </div>
          <p class="excerpt">{{ a.body }}</p>
        </article>
      } @empty {
        <div class="card muted">No articles yet.</div>
      }
    </div>
  `,
  styles: `.excerpt { margin: .75rem 0 0; color: var(--muted); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; white-space: pre-line; }`,
})
export class ArticlesList implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly api = inject(ArticlesApi);
  protected readonly articles = signal<Article[]>([]);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.list().subscribe({ next: (a) => this.articles.set(a), error: (e) => this.error.set(apiErrorMessage(e)) });
  }

  protected togglePublish(a: Article): void {
    this.api.setPublished(a.id, a.status !== 'published').subscribe({
      next: (updated) => this.replace(updated),
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
  }

  protected remove(a: Article): void {
    if (!confirm(`Delete "${a.title}"? This cannot be undone.`)) return;
    this.api.delete(a.id).subscribe({
      next: () => this.articles.update((list) => list.filter((x) => x.id !== a.id)),
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
  }

  private replace(updated: Article): void {
    this.articles.update((list) => list.map((x) => (x.id === updated.id ? updated : x)));
  }
}
