import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import { app, bearer, createUser, db, login, request, roleId } from './helpers.ts';
const { rolePermissions, syncRbacCatalog } = await import('../src/rbac/rbac.service.ts');

let superAdmin: { id: string; token: string };
let admin: { id: string; token: string };
let editor: { id: string; token: string };
let alice: { id: string; token: string };
let bob: { id: string; token: string };

async function make(email: string, roles: string[]) {
  const id = await createUser(email, roles);
  return { id, token: (await login(email)).token };
}

before(async () => {
  superAdmin = await make('root@example.com', ['super_admin']);
  admin = await make('admin@example.com', ['admin']);
  editor = await make('editor@example.com', ['editor']);
  alice = await make('alice@example.com', ['user']);
  bob = await make('bob@example.com', ['user']);
});

describe('route-level permissions (deny by default)', () => {
  it('rejects unauthenticated requests', async () => {
    assert.equal((await request(app).get('/api/users')).status, 401);
  });

  it('only allows holders of users:read to list users', async () => {
    assert.equal((await request(app).get('/api/users').set(bearer(alice.token))).status, 403);
    assert.equal((await request(app).get('/api/users').set(bearer(editor.token))).status, 403);
    assert.equal((await request(app).get('/api/users').set(bearer(admin.token))).status, 200);
  });

  it('lets admins read but not change role definitions', async () => {
    assert.equal((await request(app).get('/api/roles').set(bearer(admin.token))).status, 200);
    const res = await request(app).post('/api/roles').set(bearer(admin.token)).send({ name: 'x-role', permissions: [] });
    assert.equal(res.status, 403);
  });

  it('protects the audit log', async () => {
    assert.equal((await request(app).get('/api/audit').set(bearer(alice.token))).status, 403);
    const res = await request(app).get('/api/audit').set(bearer(admin.token));
    assert.equal(res.status, 200);
    assert.ok(res.body.items.some((e: { action: string }) => e.action === 'auth.login'));
  });
});

describe('privilege escalation guards', () => {
  it('prevents changing your own roles', async () => {
    const res = await request(app).put(`/api/users/${admin.id}/roles`).set(bearer(admin.token))
      .send({ roleIds: [roleId('super_admin')] });
    assert.equal(res.status, 403);
  });

  it('prevents an admin from granting super_admin', async () => {
    const res = await request(app).put(`/api/users/${alice.id}/roles`).set(bearer(admin.token))
      .send({ roleIds: [roleId('super_admin')] });
    assert.equal(res.status, 403);
  });

  it('prevents an admin from managing a more privileged user', async () => {
    const res = await request(app).patch(`/api/users/${superAdmin.id}`).set(bearer(admin.token)).send({ status: 'disabled' });
    assert.equal(res.status, 403);
    assert.equal((await request(app).delete(`/api/users/${superAdmin.id}`).set(bearer(admin.token))).status, 403);
  });

  it('only lets you delegate permissions you hold', async () => {
    // A "helper" can assign roles but has no article permissions.
    const created = await request(app).post('/api/roles').set(bearer(superAdmin.token))
      .send({ name: 'helper', description: 'Onboarding helper', permissions: ['users:read', 'users:assign-roles'] });
    assert.equal(created.status, 201);
    const helper = await make('helper@example.com', ['helper']);
    const carol = await createUser('carol@example.com', ['helper']);

    const escalate = await request(app).put(`/api/users/${carol}/roles`).set(bearer(helper.token))
      .send({ roleIds: [roleId('helper'), roleId('editor')] });
    assert.equal(escalate.status, 403);
    assert.match(escalate.body.error.message, /articles:/);
  });

  it('keeps super_admin locked and system roles un-renamable and undeletable', async () => {
    const lock = await request(app).patch(`/api/roles/${roleId('super_admin')}`).set(bearer(superAdmin.token))
      .send({ permissions: ['users:read'] });
    assert.equal(lock.status, 403);
    const rename = await request(app).patch(`/api/roles/${roleId('user')}`).set(bearer(superAdmin.token))
      .send({ name: 'member' });
    assert.equal(rename.status, 403);
    assert.equal((await request(app).delete(`/api/roles/${roleId('editor')}`).set(bearer(superAdmin.token))).status, 403);
  });

  it('lets system role permissions be edited, effective immediately', async () => {
    const original = (await request(app).get(`/api/roles/${roleId('editor')}`).set(bearer(superAdmin.token))).body;
    assert.equal(original.locked, false);

    const res = await request(app).patch(`/api/roles/${roleId('editor')}`).set(bearer(superAdmin.token))
      .send({ permissions: ['articles:read'] });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.effectivePermissions, ['articles:read']);
    const create = await request(app).post('/api/articles').set(bearer(editor.token)).send({ title: 'Nope', body: 'x' });
    assert.equal(create.status, 403);

    syncRbacCatalog(); // as on the next server start
    assert.deepEqual(rolePermissions(roleId('editor')), ['articles:read'], 'boot sync must not overwrite admin edits');

    const restore = await request(app).patch(`/api/roles/${roleId('editor')}`).set(bearer(superAdmin.token))
      .send({ permissions: original.permissions });
    assert.equal(restore.status, 200);
  });

  it('prevents super admins from disabling themselves', async () => {
    const res = await request(app).patch(`/api/users/${superAdmin.id}`).set(bearer(superAdmin.token)).send({ status: 'disabled' });
    assert.equal(res.status, 403); // cannot disable yourself
  });
});

describe('role changes take effect immediately', () => {
  it('applies new permissions to existing tokens and disabling revokes sessions', async () => {
    const dave = await make('dave@example.com', ['user']);
    assert.equal((await request(app).get('/api/users').set(bearer(dave.token))).status, 403);

    const grant = await request(app).put(`/api/users/${dave.id}/roles`).set(bearer(admin.token))
      .send({ roleIds: [roleId('admin')] });
    assert.equal(grant.status, 200);
    assert.equal((await request(app).get('/api/users').set(bearer(dave.token))).status, 200, 'no re-login needed');

    const revoke = await request(app).put(`/api/users/${dave.id}/roles`).set(bearer(admin.token))
      .send({ roleIds: [roleId('user')] });
    assert.equal(revoke.status, 200);
    assert.equal((await request(app).get('/api/users').set(bearer(dave.token))).status, 403);

    await request(app).patch(`/api/users/${dave.id}`).set(bearer(admin.token)).send({ status: 'disabled' });
    assert.equal((await request(app).get('/api/auth/me').set(bearer(dave.token))).status, 401);
  });
});

describe('resource ownership (articles)', () => {
  it('combines role permissions with ownership', async () => {
    const draft = await request(app).post('/api/articles').set(bearer(alice.token)).send({ title: 'Alice draft', body: 'Hello' });
    assert.equal(draft.status, 201);
    assert.deepEqual(draft.body.can, { update: true, delete: true, publish: false });
    const id = draft.body.id;

    // Bob can't even see Alice's draft — 404, not 403, to avoid leaking existence.
    assert.equal((await request(app).get(`/api/articles/${id}`).set(bearer(bob.token))).status, 404);
    // Users can't publish.
    assert.equal((await request(app).post(`/api/articles/${id}/publish`).set(bearer(alice.token))).status, 403);
    // Editors can read drafts, edit anyone's article, and publish.
    assert.equal((await request(app).patch(`/api/articles/${id}`).set(bearer(editor.token)).send({ title: 'Edited' })).status, 200);
    assert.equal((await request(app).post(`/api/articles/${id}/publish`).set(bearer(editor.token))).status, 200);

    // Once published Bob can read it but not modify or delete it.
    const seen = await request(app).get(`/api/articles/${id}`).set(bearer(bob.token));
    assert.equal(seen.status, 200);
    assert.deepEqual(seen.body.can, { update: false, delete: false, publish: false });
    assert.equal((await request(app).patch(`/api/articles/${id}`).set(bearer(bob.token)).send({ title: 'Hijack' })).status, 403);
    assert.equal((await request(app).delete(`/api/articles/${id}`).set(bearer(bob.token))).status, 403);
    // Editors lack articles:delete:any, so even they can't delete it; admins can.
    assert.equal((await request(app).delete(`/api/articles/${id}`).set(bearer(editor.token))).status, 403);
    assert.equal((await request(app).delete(`/api/articles/${id}`).set(bearer(admin.token))).status, 204);
  });
});

describe('read / write permissions', () => {
  it('serves the catalog grouped by resource, with read/write and what each grants', async () => {
    const res = await request(app).get('/api/roles/permissions').set(bearer(admin.token));
    assert.equal(res.status, 200);
    const articles = res.body.find((g: { resource: string }) => g.resource === 'articles');
    const actions = articles.permissions.map((p: { action: string }) => p.action);
    assert.ok(actions.includes('read') && actions.includes('write'));
    const write = articles.permissions.find((p: { action: string }) => p.action === 'write');
    assert.ok(write.grants.includes('articles:update:any'));
    assert.ok(write.grants.includes('articles:update:own'), 'implications are transitive');
  });

  it('write implies the granular actions of the resource', async () => {
    const role = await request(app).post('/api/roles').set(bearer(superAdmin.token))
      .send({ name: 'content-manager', permissions: ['articles:write'] });
    assert.equal(role.status, 201);
    assert.ok(role.body.effectivePermissions.includes('articles:delete:any'));

    const cm = await make('cm@example.com', ['content-manager']);
    const me = await request(app).get('/api/auth/me').set(bearer(cm.token));
    assert.ok(me.body.permissions.includes('articles:update:any'));
    assert.ok(!me.body.permissions.includes('articles:publish'), 'write does not include publish');

    const post = await request(app).post('/api/articles').set(bearer(bob.token)).send({ title: 'Bob', body: 'x' });
    assert.equal((await request(app).patch(`/api/articles/${post.body.id}`).set(bearer(cm.token)).send({ title: 'Edited' })).status, 200);
    assert.equal((await request(app).delete(`/api/articles/${post.body.id}`).set(bearer(cm.token))).status, 204);
  });

  it('read does not allow writes', async () => {
    await request(app).post('/api/roles').set(bearer(superAdmin.token)).send({ name: 'auditor', permissions: ['users:read', 'audit:read'] });
    const auditor = await make('auditor@example.com', ['auditor']);
    assert.equal((await request(app).get('/api/users').set(bearer(auditor.token))).status, 200);
    assert.equal((await request(app).patch(`/api/users/${bob.id}`).set(bearer(auditor.token)).send({ name: 'X' })).status, 403);
  });

  it('requires holding everything a permission implies before delegating it', async () => {
    // editor-lead can manage roles but only holds part of articles:write.
    await request(app).post('/api/roles').set(bearer(superAdmin.token))
      .send({ name: 'editor-lead', permissions: ['roles:write', 'articles:update:any', 'articles:create'] });
    const lead = await make('lead@example.com', ['editor-lead']);
    const res = await request(app).post('/api/roles').set(bearer(lead.token)).send({ name: 'too-much', permissions: ['articles:write'] });
    assert.equal(res.status, 403);
    assert.match(res.body.error.message, /articles:delete:any/);
  });

  it('resolves implications from the database at request time', async () => {
    const erin = await make('erin@example.com', ['user']);
    assert.equal((await request(app).get('/api/audit').set(bearer(erin.token))).status, 403);
    db.prepare("INSERT INTO permission_implications (permission, implies) VALUES ('articles:read', 'audit:read')").run();
    try {
      assert.equal((await request(app).get('/api/audit').set(bearer(erin.token))).status, 200);
    } finally {
      db.prepare("DELETE FROM permission_implications WHERE permission = 'articles:read' AND implies = 'audit:read'").run();
    }
  });
});
