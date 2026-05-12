/**
 * MCP OAuth CIMD (Client ID Metadata Document) Integration Tests
 *
 * These tests require:
 *   MCP_ENABLED=true
 *   MCP_OAUTH_ENABLED=true
 *   MCP_OAUTH_CIMD_ENABLED=true
 *   MCP_OAUTH_CIMD_ALLOW_HTTP=true    (so we can serve metadata over plain HTTP)
 *   MCP_OAUTH_CIMD_BLOCKED_TLDS=onion (override defaults to allow localhost)
 *
 * The blackbox test config includes these in directusConfig.
 *
 * NOTE: These tests cannot be run locally without Docker Compose + database setup.
 */

import crypto from 'node:crypto';
import http from 'node:http';
import { getUrl } from '@common/config';
import vendors from '@common/get-dbs-to-test';
import { USER } from '@common/variables';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

// ---------------------------------------------------------------------------
// PKCE helpers (same as mcp-oauth.test.ts)
// ---------------------------------------------------------------------------

function generatePKCE() {
	const verifier = crypto.randomBytes(32).toString('hex');
	const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
	return { verifier, challenge };
}

function extractCodeFromLocation(location: string): string {
	const url = new URL(location);
	const code = url.searchParams.get('code');
	if (!code) throw new Error(`No code in location: ${location}`);
	return code;
}

function extractSignedParams(html: string): string {
	const match = html.match(/name="signed_params"\s+value="([^"]+)"/);
	if (!match?.[1]) throw new Error('signed_params not found in consent page HTML');
	return match[1];
}

async function loginAsAdmin(baseUrl: string): Promise<string[]> {
	const res = await request(baseUrl)
		.post('/auth/login')
		.send({ email: USER.ADMIN.EMAIL, password: USER.ADMIN.PASSWORD, mode: 'session' })
		.expect(200);

	const cookies = res.headers['set-cookie'] as string[] | string | undefined;
	if (!cookies) throw new Error('No Set-Cookie header in login response');
	return Array.isArray(cookies) ? cookies : [cookies];
}

async function authorize(
	baseUrl: string,
	cookies: string[],
	clientId: string,
	redirectUri: string,
	pkce: { verifier: string; challenge: string },
): Promise<string> {
	const consentRes = await request(baseUrl)
		.get('/mcp-oauth/authorize')
		.set('Cookie', cookies)
		.query({
			client_id: clientId,
			redirect_uri: redirectUri,
			response_type: 'code',
			code_challenge: pkce.challenge,
			code_challenge_method: 'S256',
			scope: 'mcp:access',
			resource: `${baseUrl}/mcp`,
		})
		.expect(200);

	const signed_params = extractSignedParams(consentRes.text);

	const decisionRes = await request(baseUrl)
		.post('/mcp-oauth/authorize/decision')
		.set('Cookie', cookies)
		.set('Origin', baseUrl)
		.type('form')
		.send({ signed_params, approved: 'true' })
		.expect(302);

	const location = decisionRes.headers['location'] as string;
	return extractCodeFromLocation(location);
}

async function exchangeCode(
	baseUrl: string,
	clientId: string,
	code: string,
	redirectUri: string,
	codeVerifier: string,
): Promise<{ access_token: string; refresh_token: string; token_type: string; expires_in: number; scope: string }> {
	const res = await request(baseUrl)
		.post('/mcp-oauth/token')
		.type('form')
		.send({
			grant_type: 'authorization_code',
			client_id: clientId,
			code,
			redirect_uri: redirectUri,
			code_verifier: codeVerifier,
			resource: `${baseUrl}/mcp`,
		})
		.expect(200);

	return res.body;
}

// ---------------------------------------------------------------------------
// CIMD Metadata Test Server
// ---------------------------------------------------------------------------

interface MetadataServerOptions {
	path?: string;
}

class CimdMetadataServer {
	private server: http.Server | null = null;
	private port = 0;
	private metadata: Record<string, unknown> = {};
	private requestCount = 0;
	private etag: string | null = null;
	private servePath: string;

	constructor(opts: MetadataServerOptions = {}) {
		this.servePath = opts.path ?? '/metadata.json';
	}

	async start(): Promise<void> {
		return new Promise((resolve, reject) => {
			this.server = http.createServer((req, res) => {
				if (req.url !== this.servePath) {
					res.writeHead(404);
					res.end();
					return;
				}

				this.requestCount++;

				// Conditional request support (If-None-Match)
				if (this.etag && req.headers['if-none-match'] === this.etag) {
					res.writeHead(304, { ETag: this.etag });
					res.end();
					return;
				}

				const body = JSON.stringify(this.metadata);

				const headers: Record<string, string> = {
					'Content-Type': 'application/json',
					'Cache-Control': 'max-age=3600',
				};

				if (this.etag) {
					headers['ETag'] = this.etag;
				}

				res.writeHead(200, headers);
				res.end(body);
			});

			this.server.listen(0, '127.0.0.1', () => {
				const addr = this.server!.address() as { port: number };
				this.port = addr.port;
				resolve();
			});

			this.server.on('error', reject);
		});
	}

	stop(): Promise<void> {
		return new Promise((resolve) => {
			if (this.server) {
				this.server.close(() => resolve());
			} else {
				resolve();
			}
		});
	}

	getUrl(): string {
		return `http://localhost:${this.port}`;
	}

	getClientId(): string {
		return `${this.getUrl()}${this.servePath}`;
	}

	getRequestCount(): number {
		return this.requestCount;
	}

	resetRequestCount(): void {
		this.requestCount = 0;
	}

	setMetadata(doc: Record<string, unknown>): void {
		this.metadata = doc;
	}

	setEtag(etag: string | null): void {
		this.etag = etag;
	}

	/**
	 * Set a default valid metadata document with client_id matching the server URL.
	 */
	setDefaultMetadata(overrides: Record<string, unknown> = {}): void {
		this.metadata = {
			client_id: this.getClientId(),
			client_name: 'Test CIMD Client',
			redirect_uris: ['http://127.0.0.1:9876/callback'],
			grant_types: ['authorization_code'],
			token_endpoint_auth_method: 'none',
			...overrides,
		};
	}
}

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------

async function setCimdEnabled(baseUrl: string, enabled: boolean): Promise<void> {
	await request(baseUrl)
		.patch('/settings')
		.set('Authorization', `Bearer ${USER.ADMIN.TOKEN}`)
		.send({ mcp_oauth_cimd_enabled: enabled })
		.expect(200);
}

async function setDcrEnabled(baseUrl: string, enabled: boolean): Promise<void> {
	await request(baseUrl)
		.patch('/settings')
		.set('Authorization', `Bearer ${USER.ADMIN.TOKEN}`)
		.send({ mcp_oauth_dcr_enabled: enabled })
		.expect(200);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('/mcp-oauth CIMD', () => {
	const metadataServer = new CimdMetadataServer();

	beforeAll(async () => {
		await metadataServer.start();

		// Enable CIMD setting for all vendors (may already be enabled via seed)
		for (const vendor of vendors) {
			const url = getUrl(vendor);

			await request(url)
				.patch('/settings')
				.set('Authorization', `Bearer ${USER.ADMIN.TOKEN}`)
				.send({ mcp_oauth_cimd_enabled: true, mcp_oauth_dcr_enabled: true })
				.catch(() => {});
		}
	});

	afterAll(async () => {
		await metadataServer.stop();
	});

	// -----------------------------------------------------------------------
	// Full CIMD authorization flow
	// -----------------------------------------------------------------------
	describe('full CIMD OAuth flow', () => {
		it.each(vendors)(
			'%s - authorize, consent, exchange, refresh, revoke with CIMD client_id',
			async (vendor) => {
				const url = getUrl(vendor);
				const redirectUri = 'http://127.0.0.1:9876/callback';

				// Set valid metadata
				metadataServer.setDefaultMetadata();
				const clientId = metadataServer.getClientId();

				// Login
				const cookies = await loginAsAdmin(url);

				// PKCE
				const pkce = generatePKCE();

				// 1. GET /mcp-oauth/authorize with CIMD client_id -> consent page
				const consentRes = await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: redirectUri,
						response_type: 'code',
						code_challenge: pkce.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					})
					.expect(200);

				// Consent page HTML should contain signed_params
				expect(consentRes.text).toContain('signed_params');
				expect(consentRes.text).toContain('Test CIMD Client');

				const signed_params = extractSignedParams(consentRes.text);

				// 2. POST decision (approve)
				const decisionRes = await request(url)
					.post('/mcp-oauth/authorize/decision')
					.set('Cookie', cookies)
					.set('Origin', url)
					.type('form')
					.send({ signed_params, approved: 'true' })
					.expect(302);

				const location = decisionRes.headers['location'] as string;
				const code = extractCodeFromLocation(location);
				expect(code).toBeTruthy();

				// 3. Exchange code for tokens
				const tokens = await exchangeCode(url, clientId, code, redirectUri, pkce.verifier);

				expect(tokens).toMatchObject({
					access_token: expect.any(String),
					token_type: 'Bearer',
					expires_in: expect.any(Number),
					refresh_token: expect.any(String),
					scope: 'mcp:access',
				});

				// 4. Verify access token works on /mcp
				const mcpRes = await request(url)
					.post('/mcp')
					.set('Authorization', `Bearer ${tokens.access_token}`)
					.set('Accept', 'application/json')
					.send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });

				expect(mcpRes.status).toBe(200);

				// 5. Refresh token
				const refreshRes = await request(url)
					.post('/mcp-oauth/token')
					.type('form')
					.send({
						grant_type: 'refresh_token',
						client_id: clientId,
						refresh_token: tokens.refresh_token,
						resource: `${url}/mcp`,
					})
					.expect(200);

				expect(refreshRes.body).toMatchObject({
					access_token: expect.any(String),
					token_type: 'Bearer',
					expires_in: expect.any(Number),
					refresh_token: expect.any(String),
					scope: 'mcp:access',
				});

				expect(refreshRes.body.access_token).not.toBe(tokens.access_token);
				expect(refreshRes.body.refresh_token).not.toBe(tokens.refresh_token);

				const newRefreshToken = refreshRes.body.refresh_token as string;

				// 6. Revoke
				await request(url)
					.post('/mcp-oauth/revoke')
					.type('form')
					.send({ token: newRefreshToken, client_id: clientId })
					.expect(200);

				// After revocation, refresh should fail
				const afterRevokeRes = await request(url)
					.post('/mcp-oauth/token')
					.type('form')
					.send({
						grant_type: 'refresh_token',
						client_id: clientId,
						refresh_token: newRefreshToken,
						resource: `${url}/mcp`,
					});

				expect(afterRevokeRes.status).toBe(400);
				expect(afterRevokeRes.body.error).toBe('invalid_grant');
			},
			60_000,
		);
	});

	// -----------------------------------------------------------------------
	// Settings gate: mcp_oauth_cimd_enabled
	// -----------------------------------------------------------------------
	describe('CIMD settings gate', () => {
		afterEach(async () => {
			for (const vendor of vendors) {
				const url = getUrl(vendor);

				await request(url)
					.patch('/settings')
					.set('Authorization', `Bearer ${USER.ADMIN.TOKEN}`)
					.send({ mcp_oauth_cimd_enabled: true, mcp_oauth_dcr_enabled: true })
					.catch(() => {});
			}
		});

		it.each(vendors)(
			'%s - /authorize with CIMD client_id returns error when cimd disabled',
			async (vendor) => {
				const url = getUrl(vendor);
				metadataServer.setDefaultMetadata();
				const clientId = metadataServer.getClientId();

				// Disable CIMD
				await setCimdEnabled(url, false);

				const cookies = await loginAsAdmin(url);
				const pkce = generatePKCE();

				const res = await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: 'http://127.0.0.1:9876/callback',
						response_type: 'code',
						code_challenge: pkce.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					});

				expect(res.status).toBe(400);
				expect(res.text).toContain('CIMD client registration is disabled');
			},
			30_000,
		);

		it.each(vendors)(
			'%s - /authorize with CIMD client_id works after re-enabling',
			async (vendor) => {
				const url = getUrl(vendor);
				metadataServer.setDefaultMetadata();
				const clientId = metadataServer.getClientId();

				// Disable then re-enable
				await setCimdEnabled(url, false);
				await setCimdEnabled(url, true);

				const cookies = await loginAsAdmin(url);
				const pkce = generatePKCE();

				const res = await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: 'http://127.0.0.1:9876/callback',
						response_type: 'code',
						code_challenge: pkce.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					});

				// Should get 200 consent page
				expect(res.status).toBe(200);
				expect(res.text).toContain('signed_params');
			},
			30_000,
		);

		it.each(vendors)(
			'%s - POST /mcp-oauth/register returns 404 when DCR disabled',
			async (vendor) => {
				const url = getUrl(vendor);

				await setDcrEnabled(url, false);

				const res = await request(url)
					.post('/mcp-oauth/register')
					.send({
						client_name: 'test-dcr-disabled',
						redirect_uris: [`${url}/callback`],
						grant_types: ['authorization_code'],
					});

				expect(res.status).toBe(404);
				expect(res.body.error).toBe('not_found');
			},
			30_000,
		);

		it.each(vendors)(
			'%s - POST /mcp-oauth/register works after re-enabling DCR',
			async (vendor) => {
				const url = getUrl(vendor);

				await setDcrEnabled(url, false);
				await setDcrEnabled(url, true);

				const res = await request(url)
					.post('/mcp-oauth/register')
					.send({
						client_name: 'test-dcr-reenabled',
						redirect_uris: [`${url}/callback`],
						grant_types: ['authorization_code'],
					});

				expect(res.status).toBe(201);
			},
			30_000,
		);
	});

	// -----------------------------------------------------------------------
	// Invalid metadata documents
	// -----------------------------------------------------------------------
	describe('invalid metadata documents', () => {
		it.each(vendors)(
			'%s - rejects metadata with wrong client_id (does not match URL)',
			async (vendor) => {
				const url = getUrl(vendor);

				metadataServer.setMetadata({
					client_id: 'http://localhost:99999/wrong-url.json',
					client_name: 'Wrong Client ID',
					redirect_uris: ['http://127.0.0.1:9876/callback'],
					grant_types: ['authorization_code'],
					token_endpoint_auth_method: 'none',
				});

				const clientId = metadataServer.getClientId();
				const cookies = await loginAsAdmin(url);
				const pkce = generatePKCE();

				const res = await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: 'http://127.0.0.1:9876/callback',
						response_type: 'code',
						code_challenge: pkce.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					});

				expect(res.status).toBe(400);
				expect(res.text).toContain('client_id in document does not match fetch URL');
			},
			30_000,
		);

		it.each(vendors)(
			'%s - rejects metadata missing client_name',
			async (vendor) => {
				const url = getUrl(vendor);

				metadataServer.setMetadata({
					client_id: metadataServer.getClientId(),
					redirect_uris: ['http://127.0.0.1:9876/callback'],
					grant_types: ['authorization_code'],
					token_endpoint_auth_method: 'none',
				});

				const clientId = metadataServer.getClientId();
				const cookies = await loginAsAdmin(url);
				const pkce = generatePKCE();

				const res = await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: 'http://127.0.0.1:9876/callback',
						response_type: 'code',
						code_challenge: pkce.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					});

				expect(res.status).toBe(400);
				expect(res.text).toContain('client_name is required');
			},
			30_000,
		);

		it.each(vendors)(
			'%s - rejects metadata containing client_secret',
			async (vendor) => {
				const url = getUrl(vendor);

				metadataServer.setMetadata({
					client_id: metadataServer.getClientId(),
					client_name: 'Secret Client',
					client_secret: 'should-not-be-here',
					redirect_uris: ['http://127.0.0.1:9876/callback'],
					grant_types: ['authorization_code'],
					token_endpoint_auth_method: 'none',
				});

				const clientId = metadataServer.getClientId();
				const cookies = await loginAsAdmin(url);
				const pkce = generatePKCE();

				const res = await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: 'http://127.0.0.1:9876/callback',
						response_type: 'code',
						code_challenge: pkce.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					});

				expect(res.status).toBe(400);
				expect(res.text).toContain('CIMD documents must not contain client_secret');
			},
			30_000,
		);
	});

	// -----------------------------------------------------------------------
	// Cache behavior
	// -----------------------------------------------------------------------
	describe('CIMD cache behavior', () => {
		it.each(vendors)(
			'%s - second authorize request uses cached metadata (no re-fetch)',
			async (vendor) => {
				const url = getUrl(vendor);

				// Use a unique path per vendor to avoid cross-vendor cache interference
				const uniqueServer = new CimdMetadataServer({ path: `/cache-test-${vendor}.json` });
				await uniqueServer.start();

				uniqueServer.setDefaultMetadata();
				const clientId = uniqueServer.getClientId();
				const redirectUri = 'http://127.0.0.1:9876/callback';

				const cookies = await loginAsAdmin(url);

				// First authorize request -> fetches metadata
				const pkce1 = generatePKCE();

				await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: redirectUri,
						response_type: 'code',
						code_challenge: pkce1.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					})
					.expect(200);

				const countAfterFirst = uniqueServer.getRequestCount();
				expect(countAfterFirst).toBe(1);

				// Second authorize request -> should use cached client row
				const pkce2 = generatePKCE();

				await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: redirectUri,
						response_type: 'code',
						code_challenge: pkce2.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					})
					.expect(200);

				// Metadata server should NOT have received a second request
				expect(uniqueServer.getRequestCount()).toBe(1);

				await uniqueServer.stop();
			},
			30_000,
		);
	});

	// -----------------------------------------------------------------------
	// Authorization server metadata capability advertising
	// -----------------------------------------------------------------------
	describe('CIMD metadata capability advertising', () => {
		it.each(vendors)(
			'%s - server metadata advertises client_id_metadata_document_supported when CIMD enabled',
			async (vendor) => {
				const url = getUrl(vendor);

				const res = await request(url).get('/.well-known/oauth-authorization-server').expect(200);

				expect(res.body.client_id_metadata_document_supported).toBe(true);
			},
		);

		it.each(vendors)(
			'%s - server metadata omits client_id_metadata_document_supported when CIMD disabled',
			async (vendor) => {
				const url = getUrl(vendor);

				await setCimdEnabled(url, false);

				const res = await request(url).get('/.well-known/oauth-authorization-server').expect(200);

				expect(res.body.client_id_metadata_document_supported).toBeUndefined();

				// Restore
				await setCimdEnabled(url, true);
			},
			30_000,
		);
	});

	// -----------------------------------------------------------------------
	// Consent page shows CIMD-specific info
	// -----------------------------------------------------------------------
	describe('consent page metadata', () => {
		it.each(vendors)(
			'%s - consent page shows client domain for CIMD clients',
			async (vendor) => {
				const url = getUrl(vendor);
				metadataServer.setDefaultMetadata();
				const clientId = metadataServer.getClientId();
				const redirectUri = 'http://127.0.0.1:9876/callback';

				const cookies = await loginAsAdmin(url);
				const pkce = generatePKCE();

				const res = await request(url)
					.get('/mcp-oauth/authorize')
					.set('Cookie', cookies)
					.query({
						client_id: clientId,
						redirect_uri: redirectUri,
						response_type: 'code',
						code_challenge: pkce.challenge,
						code_challenge_method: 'S256',
						scope: 'mcp:access',
						resource: `${url}/mcp`,
					})
					.expect(200);

				// Consent page should contain the domain name
				expect(res.text).toContain('localhost');
			},
			30_000,
		);
	});
});
