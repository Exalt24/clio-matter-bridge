import { ok, eq, throws, report } from './_assert.mjs';
import { resolveRegion, regionKeys } from '../src/lib/regions.mjs';
import { assertRedirectUri, parseEnvFile, loadConfig } from '../src/lib/config.mjs';
import {
  buildAuthorizeUrl,
  createState,
  verifyState,
  normalizeTokenResponse,
  isExpired,
  exchangeCode,
  refreshAccessToken,
  REFRESH_SKEW_MS,
} from '../src/lib/clio-oauth.mjs';

// ---------- regions ----------
const us = resolveRegion('us');
eq(us.apiBase, 'https://app.clio.com/api/v4', 'US api base');
eq(us.authorizeUrl, 'https://app.clio.com/oauth/authorize', 'US authorize url');
eq(us.tokenUrl, 'https://app.clio.com/oauth/token', 'US token url');
eq(resolveRegion('EU').apiBase, 'https://eu.app.clio.com/api/v4', 'EU base, case-insensitive');
eq(resolveRegion(' ca ').apiBase, 'https://ca.app.clio.com/api/v4', 'CA base, trimmed');
eq(regionKeys().sort(), ['au', 'ca', 'eu', 'us'], 'four regions');
// Clio Platform authorizes at auth.api.clio.com. Manage does not. Guard the mixup.
ok(!us.authorizeUrl.includes('auth.api.clio.com'), 'Manage does not use the Platform auth host');
await throws(() => resolveRegion('uk'), /Unknown Clio region/, 'unknown region rejected');
await throws(() => resolveRegion(''), /Unknown Clio region/, 'empty region rejected');

// ---------- redirect URI rule ----------
// Positive controls first: the two forms the portal accepts.
ok(!!assertRedirectUri('https://example.com/cb'), 'CONTROL https accepted');
ok(!!assertRedirectUri('http://127.0.0.1:3000/oauth/callback'), 'CONTROL 127.0.0.1 accepted');
// The portal states: "Must use https or http://127.0.0.1, not localhost."
// Match the phrase unique to the dedicated localhost branch. Matching only
// /localhost/ passed even with the branch deleted, because the generic
// fallback error echoes the offending URI back and so contains the word.
// Caught by mutation-testing this exact assertion.
await throws(
  () => assertRedirectUri('http://localhost:3000/oauth/callback'),
  /Clio rejects "localhost"/,
  'localhost hits its dedicated branch, which names the 127.0.0.1 remedy'
);
await throws(() => assertRedirectUri('http://example.com/cb'), /must be https/, 'plain http host rejected');
await throws(() => assertRedirectUri('not a url'), /not a valid URL/, 'garbage rejected');

// ---------- env parsing ----------
const env = parseEnvFile('A=1\n# comment\n\nB="two"\nC=\'three\'\nD=has=equals\nBAD');
eq(env.A, '1', 'plain value');
eq(env.B, 'two', 'double quotes stripped');
eq(env.C, 'three', 'single quotes stripped');
eq(env.D, 'has=equals', 'only first equals splits');
ok(!('BAD' in env), 'line without equals ignored');
ok(!('# comment' in env), 'comment ignored');

// ---------- authorize URL ----------
const state = createState();
ok(state.length >= 40, 'state is long enough to resist guessing');
ok(createState() !== createState(), 'state is not reused');
const authUrl = new URL(
  buildAuthorizeUrl({ region: us, clientId: 'abc', redirectUri: 'http://127.0.0.1:3000/oauth/callback', state })
);
eq(authUrl.origin + authUrl.pathname, 'https://app.clio.com/oauth/authorize', 'authorize endpoint');
eq(authUrl.searchParams.get('response_type'), 'code', 'response_type=code');
eq(authUrl.searchParams.get('client_id'), 'abc', 'client_id passed');
eq(authUrl.searchParams.get('redirect_uri'), 'http://127.0.0.1:3000/oauth/callback', 'redirect_uri passed');
eq(authUrl.searchParams.get('state'), state, 'state passed');
eq(authUrl.searchParams.get('redirect_on_decline'), 'true', 'decline returns to the app');
ok(!authUrl.searchParams.has('client_secret'), 'secret never in a front-channel URL');

// ---------- state verification ----------
ok(verifyState(state, state), 'CONTROL matching state accepted');
ok(!verifyState(state, state.slice(0, -1) + 'X'), 'tampered state rejected');
ok(!verifyState(state, ''), 'empty state rejected');
ok(!verifyState('', ''), 'empty expected rejected, not trivially accepted');
ok(!verifyState(state, state + 'x'), 'length mismatch rejected without throwing');
ok(!verifyState(state, null), 'null state rejected');

// ---------- token normalization ----------
const T0 = 1_700_000_000_000;
const tok = normalizeTokenResponse(
  { access_token: 'at', refresh_token: 'rt', token_type: 'Bearer', expires_in: 2592000 },
  T0
);
eq(tok.accessToken, 'at', 'access token read');
eq(tok.refreshToken, 'rt', 'refresh token read');
eq(tok.expiresAt, T0 + 2592000 * 1000, 'relative expires_in converted to an absolute instant');
const noExpiry = normalizeTokenResponse({ access_token: 'at' }, T0);
eq(noExpiry.expiresAt, null, 'missing expires_in recorded as null, not as zero');
await throws(
  () => normalizeTokenResponse({ token_type: 'Bearer' }, T0),
  /no access_token/,
  'response without an access token rejected'
);

// ---------- expiry logic ----------
ok(!isExpired(tok, T0), 'CONTROL fresh token is not expired');
ok(isExpired(tok, T0 + 2592000 * 1000 + 1), 'expired token detected');
ok(isExpired(tok, T0 + 2592000 * 1000 - REFRESH_SKEW_MS + 1), 'refreshes early, inside the skew window');
ok(!isExpired(tok, T0 + 2592000 * 1000 - REFRESH_SKEW_MS - 60_000), 'does not refresh before the skew window');
ok(isExpired(null, T0), 'absent token counts as expired');
ok(isExpired({ accessToken: '' }, T0), 'blank access token counts as expired');
ok(!isExpired(noExpiry, T0 + 10 ** 12), 'unknown expiry is trusted until a 401 says otherwise');

// ---------- token exchange wire format ----------
function recordingFetch(status, payload) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init, body: Object.fromEntries(new URLSearchParams(init.body)) });
    return {
      ok: status < 400,
      status,
      text: async () => JSON.stringify(payload),
    };
  };
  return { impl, calls };
}

let rec = recordingFetch(200, { access_token: 'at2', refresh_token: 'rt2', expires_in: 100 });
await exchangeCode(
  { region: us, clientId: 'cid', clientSecret: 'sec', redirectUri: 'http://127.0.0.1:3000/cb', code: 'thecode' },
  { fetchImpl: rec.impl, now: T0 }
);
eq(rec.calls[0].url, 'https://app.clio.com/oauth/token', 'posts to the token endpoint');
eq(rec.calls[0].init.headers['content-type'], 'application/x-www-form-urlencoded', 'form encoded, not JSON');
eq(rec.calls[0].body.grant_type, 'authorization_code', 'grant_type=authorization_code');
eq(rec.calls[0].body.code, 'thecode', 'code sent');
eq(rec.calls[0].body.client_secret, 'sec', 'secret sent on the back channel');
eq(rec.calls[0].body.redirect_uri, 'http://127.0.0.1:3000/cb', 'redirect_uri echoed on exchange');

// A refresh response that omits refresh_token must not wipe the stored one.
rec = recordingFetch(200, { access_token: 'at3', expires_in: 100 });
const refreshed = await refreshAccessToken(
  { region: us, clientId: 'cid', clientSecret: 'sec', refreshToken: 'keepme' },
  { fetchImpl: rec.impl, now: T0 }
);
eq(rec.calls[0].body.grant_type, 'refresh_token', 'grant_type=refresh_token');
eq(refreshed.refreshToken, 'keepme', 'existing refresh token preserved when the response omits it');
eq(refreshed.accessToken, 'at3', 'new access token taken');

await throws(
  () => refreshAccessToken({ region: us, clientId: 'c', clientSecret: 's', refreshToken: null }, {}),
  /re-authorization required/,
  'refresh without a token fails loudly rather than silently'
);

// Error classification, because "invalid_client" and "invalid_grant" have
// completely different remedies and both arrive as a 400.
rec = recordingFetch(400, { error: 'invalid_client' });
try {
  await exchangeCode(
    { region: us, clientId: 'c', clientSecret: 'wrong', redirectUri: 'http://127.0.0.1:3000/cb', code: 'x' },
    { fetchImpl: rec.impl }
  );
  ok(false, 'invalid_client should throw');
} catch (err) {
  eq(err.kind, 'invalid_client', 'invalid_client classified (means the id/secret pair is wrong or swapped)');
  eq(err.status, 400, 'status preserved');
}
rec = recordingFetch(400, { error: 'invalid_grant' });
try {
  await exchangeCode(
    { region: us, clientId: 'c', clientSecret: 's', redirectUri: 'http://127.0.0.1:3000/cb', code: 'stale' },
    { fetchImpl: rec.impl }
  );
  ok(false, 'invalid_grant should throw');
} catch (err) {
  eq(err.kind, 'invalid_grant', 'invalid_grant classified (means the code was reused or expired)');
}

// ---------- config ----------
const cfg = loadConfig({
  CLIO_CLIENT_ID: 'id',
  CLIO_CLIENT_SECRET: 'secret',
  CLIO_REGION: 'us',
  CLIO_REDIRECT_URI: 'http://127.0.0.1:3000/oauth/callback',
});
eq(cfg.region.key, 'us', 'CONTROL config loads with a full set');
await throws(
  () => loadConfig({ CLIO_CLIENT_SECRET: 'secret' }),
  /CLIO_CLIENT_ID/,
  'missing client id named explicitly'
);
await throws(
  () => loadConfig({ CLIO_CLIENT_ID: 'id' }),
  /CLIO_CLIENT_SECRET/,
  'missing secret named explicitly'
);
await throws(
  () => loadConfig({ CLIO_CLIENT_ID: 'i', CLIO_CLIENT_SECRET: 's', CLIO_REDIRECT_URI: 'http://localhost:3000/cb' }),
  /Clio rejects "localhost"/,
  'localhost redirect caught at startup, not mid-flow'
);

report('oauth');
