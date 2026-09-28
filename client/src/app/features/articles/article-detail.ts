import { DatePipe } from '@angular/common';
import { Component, inject, input, OnInit, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ArticlesApi } from '../../core/api/articles.api';
import type { Article } from '../../core/api/api.models';
import { apiErrorMessage } from '../../core/http/errors';
import { ensureValid } from '../../core/forms';

/** View, create (`/articles/new`) and edit (`/articles/:id/edit`) in one component. */
@Component({
  selector: 'app-article-detail',
  imports: [ReactiveFormsModule, RouterLink, DatePipe],
  template: `
    <p><a routerLink="/articles" class="small">← All articles</a></p>
    @if (error()) { <div class="alert alert-error">{{ error() }}</div> }

    @if (editing()) {
      <form [formGroup]="form" (ngSubmit)="save()" class="card stack">
        <h1>{{ id() ? 'Edit article' : 'New article' }}</h1>
        <div class="field">
          <label for="title">Title</label>
          <input id="title" type="text" formControlName="title" />
        </div>
        <div class="field">
          <label for="body">Body</label>
          <textarea id="body" formControlName="body" rows="12"></textarea>
        </div>
        <div class="row">
          <button class="btn btn-primary" [disabled]="busy()">Save</button>
          <a class="btn btn-ghost" [routerLink]="id() ? ['/articles', id()] : ['/articles']">Cancel</a>
        </div>
      </form>
    } @else if (article(); as a) {
      <article class="card stack">
        <div class="spread">
          <h1 style="margin: 0">{{ a.title }}</h1>
          @if (a.can.update) { <a class="btn btn-sm" [routerLink]="['/articles', a.id, 'edit']">Edit</a> }
        </div>
        <p class="small muted">
          {{ a.authorName }} · {{ a.status === 'published' ? 'published ' + (a.publishedAt | date: 'medium') : 'draft' }}
        </p>
        <div class="body">{{ a.body }}</div>
      </article>
    }
  `,
  styles: `.body { white-space: pre-line; }`,
})
export class ArticleDetail implements OnInit {
  /** Bound from the route via withComponentInputBinding(). */
  readonly id = input<string>();
  readonly mode = input<'view' | 'edit'>('view');

  private readonly api = inject(ArticlesApi);
  private readonly router = inject(Router);
  protected readonly form = inject(NonNullableFormBuilder).group({
    title: ['', [Validators.required, Validators.maxLength(200)]],
    body: ['', [Validators.required, Validators.maxLength(20000)]],
  });
  protected readonly article = signal<Article | null>(null);
  protected readonly editing = signal(false);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    const id = this.id();
    if (!id) {
      this.editing.set(true);
      return;
    }
    this.api.get(id).subscribe({
      next: (a) => {
        this.article.set(a);
        if (this.mode() === 'edit') {
          if (!a.can.update) {
            void this.router.navigate(['/forbidden']);
            return;
          }
          this.form.setValue({ title: a.title, body: a.body });
          this.editing.set(true);
        }
      },
      error: (e) => this.error.set(apiErrorMessage(e)),
    });
  }

  protected save(): void {
    if (!ensureValid(this.form)) return;
    this.busy.set(true);
    this.error.set(null);
    const id = this.id();
    const req = id ? this.api.update(id, this.form.getRawValue()) : this.api.create(this.form.getRawValue());
    req.subscribe({
      next: (a) => void this.router.navigate(['/articles', a.id]),
      error: (e) => { this.busy.set(false); this.error.set(apiErrorMessage(e)); },
    });
  }
}
