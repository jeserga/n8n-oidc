'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { startStack, users } = require('./harness');

let stack;
let ownerId;
const cookie = (response, name) => response.headers.getSetCookie().find(line => line.startsWith(name + '='));
async function login(user, mutateCookie = false) {
	await stack.setIdp({ user, tamper: null });
	const start = await fetch(stack.base + '/auth/oidc/login', { redirect: 'manual' });
	const tx = cookie(start, '__Host-n8n-oidc-tx');
	assert.match(tx, /; Path=\//);
	assert.match(tx, /; Secure/);
	assert.match(tx, /; HttpOnly/);
	assert.match(tx, /; SameSite=Lax/);
	assert.doesNotMatch(tx, /; Domain=/i);
	const authorize = await fetch(start.headers.get('location'), { redirect: 'manual' });
	let pair = tx.split(';')[0];
	if (mutateCookie) pair = pair.slice(0, -3) + 'xxx';
	const callback = await fetch(authorize.headers.get('location'), { redirect: 'manual', headers: { Cookie: pair } });
	const cleared = cookie(callback, '__Host-n8n-oidc-tx');
	assert.match(cleared, /; Secure/);
	assert.match(cleared, /Expires=Thu, 01 Jan 1970/);
	return { callback, auth: cookie(callback, 'n8n-auth')?.split(';')[0] };
}
async function me(auth) {
	const response = await fetch(stack.base + '/rest/login', { headers: { Cookie: auth } });
	assert.equal(response.status, 200);
	return (await response.json()).data;
}
test.before(async () => {
	stack = await startStack({ n8nPort: 5689, idpPort: 10000, env: {
		N8N_SECURE_COOKIE: 'true',
		N8N_USER_MANAGEMENT_JWT_DURATION_HOURS: '1',
		N8N_USER_MANAGEMENT_JWT_REFRESH_TIMEOUT_HOURS: '-1',
		OIDC_AUTO_PROVISION: 'false',
		OIDC_SYNC_PROFILE: 'false',
		OIDC_ALLOWED_GROUPS: '',
	} });
});
test.after(async () => { if (stack) await stack.stop(); });
test('secure transaction cookies are issued and cleared with matching host-only attributes', async () => {
	const { auth } = await login(users.owner);
	assert.ok(auth);
	ownerId = (await me(auth)).id;
});
test('a linked subject keeps its native account, email, name and owner role when sync is off', async () => {
	const { auth } = await login({ ...users.owner, email: 'different@example.net', given_name: 'Changed' });
	const current = await me(auth);
	assert.equal(current.id, ownerId);
	assert.equal(current.email, users.owner.email);
	assert.equal(current.firstName, users.owner.given_name);
	assert.equal(current.role, 'global:owner');
});
test('auto-provision off refuses an unknown subject even with a verified email', async () => {
	const { callback, auth } = await login(users.member);
	assert.equal(auth, undefined);
	assert.equal(new URL(callback.headers.get('location')).searchParams.get('oidc_error'), 'not_provisioned');
});
test('tampering with the authenticated encrypted transaction refuses the login', async () => {
	const { callback, auth } = await login(users.owner, true);
	assert.equal(auth, undefined);
	assert.equal(new URL(callback.headers.get('location')).searchParams.get('oidc_error'), 'session_expired');
});
test('the native SSO session is one hour and logout prevents cookie replay', async () => {
	const { auth } = await login(users.owner);
	const payload = JSON.parse(Buffer.from(auth.slice('n8n-auth='.length).split('.')[1], 'base64url'));
	assert.equal(payload.exp - payload.iat, 3600);
	await me(auth);
	const logout = await fetch(stack.base + '/rest/logout', { method: 'POST', headers: { Cookie: auth } });
	assert.equal(logout.status, 200);
	assert.equal((await fetch(stack.base + '/rest/login', { headers: { Cookie: auth } })).status, 401);
});
