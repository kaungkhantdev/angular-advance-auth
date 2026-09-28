import { HttpClient } from '@angular/common/http';
import { inject, Service } from '@angular/core';
import type { Article } from './api.models';

@Service()
export class ArticlesApi {
  private readonly http = inject(HttpClient);
  private readonly base = '/api/articles';

  list() {
    return this.http.get<Article[]>(this.base);
  }
  get(id: string) {
    return this.http.get<Article>(`${this.base}/${id}`);
  }
  create(body: { title: string; body: string }) {
    return this.http.post<Article>(this.base, body);
  }
  update(id: string, body: { title?: string; body?: string }) {
    return this.http.patch<Article>(`${this.base}/${id}`, body);
  }
  delete(id: string) {
    return this.http.delete<void>(`${this.base}/${id}`);
  }
  setPublished(id: string, published: boolean) {
    return this.http.post<Article>(`${this.base}/${id}/${published ? 'publish' : 'unpublish'}`, {});
  }
}
