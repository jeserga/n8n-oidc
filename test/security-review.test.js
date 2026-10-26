'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const t = require('../hooks')[Symbol.for('n8n-oidc.internals')];

test('HTTPS transaction cookies have the browser-enforced host-only prefix', () => {
	assert.deepEqual(t.transactionCookieSettings(true), { name: '__Host-n8n-oidc-tx', path: '/' });
	assert.deepEqual(t.transactionCookieSettings(false), { name: 'n8n-oidc-tx', path: '/auth/oidc' });
});

test('untrusted log strings cannot inject lines or terminal escape sequences', () => {
	const value = t.logValue('denied\nFORGED\r\x1b[2J');
	assert.equal(value, 'denied FORGED  [2J');
	assert.equal(t.logValue(new Error('bad\ninput')), 'bad input');
	assert.equal(t.logValue('x'.repeat(5000)).length, 2048);
});

test('provider error details and non-JSON response bodies are not reflected into logs', async () => {
	const original = global.fetch;
	try {
		global.fetch = async () => new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'private-code-or-secret' }), { status: 400 });
		await assert.rejects(t.fetchJson('https://issuer.example/token'), error => error.message.includes('invalid_grant') && !error.message.includes('private-code-or-secret'));
		global.fetch = async () => new Response('private-code-or-secret', { status: 500 });
		await assert.rejects(t.fetchJson('https://issuer.example/token'), error => !error.message.includes('private-code-or-secret'));
	} finally { global.fetch = original; }
});

for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint']) {
	test('HTTPS discovery rejects a downgrade of ' + field, async () => {
		const original = global.fetch;
		try {
			const document = { issuer: 'https://issuer.example', authorization_endpoint: 'https://issuer.example/authorize', token_endpoint: 'https://issuer.example/token', jwks_uri: 'https://issuer.example/keys', userinfo_endpoint: 'https://issuer.example/userinfo' };
			document[field] = 'http://attacker.example/steal';
			global.fetch = async () => new Response(JSON.stringify(document));
			const provider = new t.OidcProvider({ issuerUrl: document.issuer, usePkce: true });
			await assert.rejects(provider.getDiscovery(), /downgrade HTTPS/);
		} finally { global.fetch = original; }
	});
}

test('signed ID tokens with non-finite numeric dates are rejected', async () => {
	const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const now = Math.floor(Date.now() / 1000);
	const provider = new t.OidcProvider({ issuerUrl: 'https://issuer.example', clientId: 'client' });
	provider.discovery = { issuer: 'https://issuer.example', id_token_signing_alg_values_supported: ['RS256'] };
	provider.discoveryFetchedAt = Date.now();
	provider.jwks = [{ ...publicKey.export({ format: 'jwk' }), kid: 'review', alg: 'RS256' }];
	provider.jwksFetchedAt = Date.now();
	for (const field of ['exp', 'iat', 'nbf']) {
		let payload = JSON.stringify({ iss: 'https://issuer.example', aud: 'client', sub: 'user', nonce: 'nonce', iat: now, exp: now + 300, [field]: 'NON_FINITE' });
		payload = payload.replace('"NON_FINITE"', '1e999');
		const input = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'review' })).toString('base64url') + '.' + Buffer.from(payload).toString('base64url');
		const signature = crypto.sign('sha256', Buffer.from(input), privateKey).toString('base64url');
		await assert.rejects(provider.validateIdToken(input + '.' + signature, 'nonce'));
	}
});
