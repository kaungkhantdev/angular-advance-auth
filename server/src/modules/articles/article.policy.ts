import type { Principal } from '../../rbac/rbac.service.ts';

/**
 * Resource-level authorization (RBAC + ownership). Route guards answer "may this
 * role do X to articles at all?"; these pure functions answer "to *this* article?".
 * Keeping them pure and side-effect free makes them trivial to unit test and reuse
 * (e.g. to compute the `can` flags sent to the UI).
 */
export interface ArticleLike {
  authorId: string;
  status: 'draft' | 'published';
}

const has = (p: Principal, perm: Parameters<Principal['permissions']['has']>[0]) => p.permissions.has(perm);
const owns = (p: Principal, a: ArticleLike) => a.authorId === p.userId;

export const articlePolicy = {
  read: (p: Principal, a: ArticleLike) =>
    has(p, 'articles:read') && (a.status === 'published' || owns(p, a) || has(p, 'articles:read-drafts')),

  update: (p: Principal, a: ArticleLike) =>
    has(p, 'articles:update:any') || (has(p, 'articles:update:own') && owns(p, a)),

  delete: (p: Principal, a: ArticleLike) =>
    has(p, 'articles:delete:any') || (has(p, 'articles:delete:own') && owns(p, a)),

  publish: (p: Principal, _a: ArticleLike) => has(p, 'articles:publish'),
};

export function articleAbilities(p: Principal, a: ArticleLike) {
  return { update: articlePolicy.update(p, a), delete: articlePolicy.delete(p, a), publish: articlePolicy.publish(p, a) };
}
