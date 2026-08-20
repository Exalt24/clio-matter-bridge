import { ok, eq, report } from './_assert.mjs';
import { loadConfig } from '../src/lib/config.mjs';
import { ClioClient } from '../src/lib/clio-client.mjs';
import {
  loadTokens,
  refreshAccessToken,
  isExpired,
  saveTokens,
} from '../src/lib/clio-oauth.mjs';

// LIVE suite. Hits the real Clio API with a real token, so it needs `npm run auth`
// and seeded records first. Everything here is a claim that could not be made
// from unit tests: that the calls work, that pagination turns real pages, and
// that the refresh grant actually succeeds against the live endpoint.
//
// Read-only apart from the refresh, which rotates the stored access token. It
// creates and deletes nothing.

const config = loadConfig();
const client = new ClioClient(config);

// ---------- authentication actually works ----------
const me = await client.request('/users/who_am_i', { fields: 'id,name,email,account{id,name}' });
ok(!!me?.data?.id, 'authenticated call returns a user id');
ok(typeof me.data.name === 'string' && me.data.name.length > 0, 'user has a name');
console.log(`  account: ${me.data.account?.name ?? '(none)'}  user: ${me.data.name}`);

// ---------- rate limit headers are present and sane ----------
const rl = client.lastRateLimit;
ok(Number.isFinite(rl.limit) && rl.limit > 0, `X-RateLimit-Limit present (${rl.limit})`);
ok(Number.isFinite(rl.remaining), `X-RateLimit-Remaining present (${rl.remaining})`);
ok(rl.remaining <= rl.limit, 'remaining never exceeds the limit');
// The limit VARIES by time of day, exactly as Clio documents: 50/min at peak,
// higher off-peak. This assertion used to be `rl.limit !== 50`, which encoded my
// wrong belief that the docs were incorrect, and it duly failed the moment the
// window moved to peak. Assert the CONTRACT instead: a positive limit, and a
// client that has paced itself to whatever it was given.
ok(rl.limit >= 50, `limit is at least the documented peak floor (observed ${rl.limit})`);
ok(client.minIntervalMs >= 100, `pacing derived from the header (${client.minIntervalMs}ms)`);
ok(
  client.minIntervalMs <= Math.ceil(60000 / (rl.limit * (2 / 3))) + 1,
  'pacing is no slower than the observed budget requires'
);

// ---------- cursor pagination turns real pages ----------
// pageSize is deliberately tiny so the seeded record count forces several
// round trips. A single-page result would prove nothing about paging.
const matters = [];
for await (const m of client.paginate('/matters', {
  fields: 'id,display_number,description,status',
  pageSize: 2,
})) {
  matters.push(m);
}
ok(matters.length > 0, `matters returned (${matters.length})`);
ok(matters.length > 2, `more records than one page of 2, so paging really advanced (${matters.length})`);
const ids = matters.map((m) => m.id);
eq(new Set(ids).size, ids.length, 'no duplicate records across page boundaries');
// Cursor paging requires order=id(asc); if that were dropped the sequence would
// not be monotonic and pages could repeat or skip.
const sorted = [...ids].sort((a, b) => a - b);
eq(ids, sorted, 'ids arrive in ascending order, confirming order=id(asc) was applied');
ok(
  matters.every((m) => typeof m.description === 'string'),
  'every record carries the requested description field'
);

// ---------- the fields parameter genuinely controls the response ----------
const minimal = await client.request('/matters', { query: { limit: 1 } });
const expanded = await client.request('/matters', {
  fields: 'id,description,status,client{id,name}',
  query: { limit: 1 },
});
const minKeys = Object.keys(minimal.data[0] ?? {});
const expKeys = Object.keys(expanded.data[0] ?? {});
ok(expKeys.length > minKeys.length, `fields expands the response (${minKeys.length} -> ${expKeys.length} keys)`);
ok(!minKeys.includes('description'), 'omitting fields really does withhold columns, as documented');
ok(expKeys.includes('client'), 'nested resource requested via brace syntax is returned');
const withClient = expanded.data[0];
ok(
  withClient.client === null || typeof withClient.client === 'object',
  'nested client resolves to an object or an explicit null'
);

// ---------- change detection filters, rather than being ignored ----------
const future = new Date(Date.now() + 86_400_000).toISOString();
const none = await client.request('/matters', { fields: 'id', query: { updated_since: future, limit: 5 } });
eq(none.data.length, 0, 'updated_since with a future date returns nothing, so it is honoured not ignored');
const past = new Date('2020-01-01T00:00:00Z').toISOString();
const some = await client.request('/matters', { fields: 'id', query: { updated_since: past, limit: 5 } });
ok(some.data.length > 0, 'updated_since with a past date returns records');

// ---------- a bad request fails the way the client expects ----------
try {
  await client.request('/matters', { fields: 'id', query: { limit: 1, order: 'not_a_column(asc)' } });
  ok(false, 'an invalid order column should have been rejected');
} catch (err) {
  ok(err.status >= 400, `invalid order rejected with ${err.status}`);
  ok(!!err.body, 'error body captured for diagnosis');
}

// ---------- the refresh grant works against the LIVE endpoint ----------
// This is the gap unit tests cannot close: the mock proves the wire format, not
// that Clio accepts it. Rotating a valid token is the only real proof.
const before = loadTokens(config.tokenPath);
ok(!!before?.refreshToken, 'a refresh token is stored');
ok(!isExpired(before), 'CONTROL stored access token is currently valid');
const rotated = await refreshAccessToken({
  region: config.region,
  clientId: config.clientId,
  clientSecret: config.clientSecret,
  refreshToken: before.refreshToken,
});
ok(!!rotated.accessToken, 'refresh returned a new access token');
ok(!!rotated.refreshToken, 'refresh response still carries a usable refresh token');
ok(rotated.expiresAt > Date.now(), 'refreshed token expires in the future');
saveTokens(config.tokenPath, rotated);

// And the rotated token must actually authenticate, otherwise "refresh worked"
// is a claim about a 200 response rather than about a usable credential.
const afterClient = new ClioClient(config);
const me2 = await afterClient.request('/users/who_am_i', { fields: 'id' });
eq(me2.data.id, me.data.id, 'the refreshed token authenticates as the same user');

report('live');
