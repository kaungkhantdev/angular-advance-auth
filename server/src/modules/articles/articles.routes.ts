import { Router } from 'express';
import { z } from 'zod';
import { db } from '../../db/database.ts';
import { uuid } from '../../lib/crypto.ts';
import { forbidden, notFound } from '../../lib/errors.ts';
import { authenticate, authOf, requireAnyPermission, requirePermission } from '../../middleware/auth.ts';
import { parse } from '../../middleware/errors.ts';
import { clientContext } from '../../middleware/security.ts';
import type { Principal } from '../../rbac/rbac.service.ts';
import { audit } from '../audit/audit.service.ts';
import { articleAbilities, articlePolicy } from './article.policy.ts';

interface ArticleRow {
  id: string;
  authorId: string;
  authorName: string;
  title: string;
  body: string;
  status: 'draft' | 'published';
  publishedAt: number | null;
  createdAt: number;
  updatedAt: number;
}

const SELECT = `
  SELECT a.id, a.author_id AS authorId, u.name AS authorName, a.title, a.body, a.status,
         a.published_at AS publishedAt, a.created_at AS createdAt, a.updated_at AS updatedAt
  FROM articles a JOIN users u ON u.id = a.author_id`;

const withAbilities = (p: Principal, a: ArticleRow) => ({ ...a, can: articleAbilities(p, a) });

/**
 * Loads an article the caller is allowed to see. Returns 404 (not 403) for drafts
 * the caller can't read, so the existence of other people's drafts isn't leaked.
 */
function loadReadable(p: Principal, id: string): ArticleRow {
  const a = db.prepare(`${SELECT} WHERE a.id = ?`).get(id) as ArticleRow | undefined;
  if (!a || !articlePolicy.read(p, a)) throw notFound('Article');
  return a;
}

export const articlesRouter = Router();
articlesRouter.use(authenticate);

const idParam = z.object({ id: z.uuid() });
const content = z.object({ title: z.string().trim().min(1).max(200), body: z.string().trim().min(1).max(20_000) });

articlesRouter.get('/', requirePermission('articles:read'), (req, res) => {
  const p = authOf(req).principal;
  // Filter in SQL with the same rule as articlePolicy.read, so pagination stays correct.
  const rows = p.permissions.has('articles:read-drafts')
    ? db.prepare(`${SELECT} ORDER BY a.updated_at DESC`).all()
    : db.prepare(`${SELECT} WHERE a.status = 'published' OR a.author_id = ? ORDER BY a.updated_at DESC`).all(p.userId);
  res.json((rows as unknown as ArticleRow[]).map((a) => withAbilities(p, a)));
});

articlesRouter.get('/:id', requirePermission('articles:read'), (req, res) => {
  const p = authOf(req).principal;
  res.json(withAbilities(p, loadReadable(p, parse(idParam, req.params).id)));
});

articlesRouter.post('/', requirePermission('articles:create'), (req, res) => {
  const body = parse(content, req.body);
  const { principal } = authOf(req);
  const id = uuid();
  const now = Date.now();
  db.prepare('INSERT INTO articles (id, author_id, title, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, principal.userId, body.title, body.body, now, now);
  audit(clientContext(req), { action: 'articles.create', targetType: 'article', targetId: id });
  res.status(201).json(withAbilities(principal, loadReadable(principal, id)));
});

articlesRouter.patch('/:id', requireAnyPermission('articles:update:own', 'articles:update:any'), (req, res) => {
  const { id } = parse(idParam, req.params);
  const body = parse(content.partial().strict(), req.body);
  const p = authOf(req).principal;
  const article = loadReadable(p, id);
  if (!articlePolicy.update(p, article)) throw forbidden('You can only edit your own articles');
  db.prepare('UPDATE articles SET title = COALESCE(?, title), body = COALESCE(?, body), updated_at = ? WHERE id = ?')
    .run(body.title ?? null, body.body ?? null, Date.now(), id);
  audit(clientContext(req), { action: 'articles.update', targetType: 'article', targetId: id, metadata: { ownedByActor: article.authorId === p.userId } });
  res.json(withAbilities(p, loadReadable(p, id)));
});

articlesRouter.delete('/:id', requireAnyPermission('articles:delete:own', 'articles:delete:any'), (req, res) => {
  const { id } = parse(idParam, req.params);
  const p = authOf(req).principal;
  const article = loadReadable(p, id);
  if (!articlePolicy.delete(p, article)) throw forbidden('You can only delete your own articles');
  db.prepare('DELETE FROM articles WHERE id = ?').run(id);
  audit(clientContext(req), { action: 'articles.delete', targetType: 'article', targetId: id, metadata: { title: article.title } });
  res.status(204).end();
});

for (const [path, status] of [['publish', 'published'], ['unpublish', 'draft']] as const) {
  articlesRouter.post(`/:id/${path}`, requirePermission('articles:publish'), (req, res) => {
    const { id } = parse(idParam, req.params);
    const p = authOf(req).principal;
    loadReadable(p, id);
    db.prepare('UPDATE articles SET status = ?, published_at = ?, updated_at = ? WHERE id = ?')
      .run(status, status === 'published' ? Date.now() : null, Date.now(), id);
    audit(clientContext(req), { action: `articles.${path}`, targetType: 'article', targetId: id });
    res.json(withAbilities(p, loadReadable(p, id)));
  });
}
