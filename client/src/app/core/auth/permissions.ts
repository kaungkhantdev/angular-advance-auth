/**
 * Permissions are defined and resolved by the server (`resource:action`, e.g.
 * `articles:publish`). The client never keeps its own list: the signed-in user's
 * permissions arrive from `/api/auth/me`, and the full catalog from `/api/roles/permissions`.
 *
 * Client-side checks are UX only — the API enforces every rule.
 */
export type Permission = string;
