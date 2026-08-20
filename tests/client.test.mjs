import { ok, eq, throws, report } from './_assert.mjs';
import {
  buildFields,
  assertFieldsLength,
  parseRateLimit,
  ClioClient,
  ClioApiError,
  FIELDS_MAX_LENGTH,
  OFFSET_PAGINATION_MAX_RECORDS,
} from '../src/lib/clio-client.mjs';
import { resolveRegion } from '../src/lib/regions.mjs';

// This suite exists because a MUTATION SWEEP found the client had none. Breaking
// the fields length cap left every other suite green, which means the documented
// 1000-character limit was enforced in code and asserted nowhere. package.json
// also referenced tests/client.test.mjs, which did not exist, so `test:offline`
// was silently running one fewer file than it claimed.

const region = resolveRegion('us');
const cfg = {
  clientId: 'id', clientSecret: 'secret', region,
  redirectUri: 'http://127.0.0.1:3000/oauth/callback', tokenPath: '.no-tokens',
};

// ---------- fields builder ----------
eq(buildFields('id,name'), 'id,name', 'CONTROL a string passes through');
eq(buildFields(['id', 'name']), 'id,name', 'an array joins with commas');
eq(buildFields({ id: true, name: true }), 'id,name', 'an object of true flags flattens');
eq(
  buildFields({ id: true, client: ['id', 'name'] }),
  'id,client{id,name}',
  'a nested array becomes Clio brace syntax'
);
eq(
  buildFields({ id: true, client: { id: true, address: ['city'] } }),
  'id,client{id,address{city}}',
  'nesting recurses'
);
eq(buildFields({ id: true, skip: false, gone: null }), 'id', 'false and null keys are dropped');
await throws(() => buildFields(42), /must be a string, array, or object/, 'a number is rejected');
await throws(() => buildFields(null), /must be a string, array, or object/, 'null is rejected');

// ---------- THE CAP. This is the guard the sweep found untested. ----------
eq(FIELDS_MAX_LENGTH, 1000, 'the documented ceiling is recorded as a constant');
const justUnder = 'a'.repeat(FIELDS_MAX_LENGTH);
eq(assertFieldsLength(justUnder).length, FIELDS_MAX_LENGTH, 'CONTROL exactly at the limit is allowed');
await throws(
  () => assertFieldsLength('a'.repeat(FIELDS_MAX_LENGTH + 1)),
  /Clio rejects anything over 1000/,
  'one character over the limit is rejected'
);
await throws(
  () => buildFields(Array.from({ length: 300 }, (_, i) => `field_number_${i}`)),
  /Clio rejects anything over 1000/,
  'the cap applies through buildFields, not only the raw helper'
);
// The error must carry the actual length, because "too long" without a number
// gives the caller nothing to trim against.
try {
  assertFieldsLength('a'.repeat(1234));
} catch (err) {
  ok(err instanceof ClioApiError, 'the cap raises the typed API error');
  ok(/1234 characters/.test(err.message), 'the message states the offending length');
}

// ---------- rate limit header parsing ----------
const rl = parseRateLimit({ 'x-ratelimit-limit': '600', 'x-ratelimit-remaining': '599', 'x-ratelimit-reset': '1787217780' });
eq(rl.limit, 600, 'limit parsed');
eq(rl.remaining, 599, 'remaining parsed');
eq(rl.reset, 1787217780, 'reset parsed as a number');
const missing = parseRateLimit({});
eq(missing.limit, null, 'absent headers parse to null, not zero');
eq(parseRateLimit({ 'x-ratelimit-limit': 'nonsense' }).limit, null, 'unparseable header is null');
// Header lookup must be case-insensitive: node lowercases, other stacks do not.
eq(parseRateLimit({ 'X-RateLimit-Limit': '50' }).limit, 50, 'header match is case-insensitive');

// ---------- adaptive pacing, the fix for my own wrong assumption ----------
// The limit VARIES by time of day (50 at peak, higher off-peak, both documented).
// Hardcoding either number is the mistake this behaviour replaces.
function fakeFetch(limit) {
  return async () => ({
    ok: true,
    status: 200,
    headers: new Map([
      ['x-ratelimit-limit', String(limit)],
      ['x-ratelimit-remaining', String(limit - 1)],
      ['x-ratelimit-reset', '1787217780'],
    ]),
    text: async () => JSON.stringify({ data: [] }),
  });
}
// Map needs a .get, which it has, and parseRateLimit uses headers.get when present.
const mk = (limit) => new ClioClient(cfg, {
  fetchImpl: fakeFetch(limit),
  sleepImpl: async () => {},
  tokenProvider: async () => ({ accessToken: 'tok' }),
});

const slow = mk(50);
eq(slow.minIntervalMs, 1200, 'CONTROL opens at the conservative 50/min guess');
await slow.request('/matters', { fields: 'id' });
ok(slow.minIntervalMs >= 1200, `a limit of 50 keeps pacing slow (${slow.minIntervalMs}ms)`);

const fast = mk(600);
await fast.request('/matters', { fields: 'id' });
ok(fast.minIntervalMs < 1200, `a limit of 600 speeds pacing up (${fast.minIntervalMs}ms)`);
ok(fast.minIntervalMs >= 100, 'but never below the 100ms floor');
// The point of the whole change: the same client adapts rather than being told.
ok(fast.minIntervalMs < slow.minIntervalMs, 'pacing tracks the header rather than a constant');

const fixed = new ClioClient(cfg, {
  fetchImpl: fakeFetch(600), sleepImpl: async () => {},
  tokenProvider: async () => ({ accessToken: 'tok' }),
  adaptFromHeaders: false, minIntervalMs: 900,
});
await fixed.request('/matters', { fields: 'id' });
eq(fixed.minIntervalMs, 900, 'adaptation can be switched off for a caller that wants control');

// ---------- paging constant ----------
eq(OFFSET_PAGINATION_MAX_RECORDS, 10000, 'the documented offset ceiling is recorded');

// ---------- error classification ----------
const paging = new ClioApiError('x', { status: 422, body: { error: { message: 'offset too large' } } });
ok(paging.isPagingLimit, 'a 422 mentioning offset is classed as the paging ceiling');
const other422 = new ClioApiError('x', { status: 422, body: { error: { message: 'bad argument' } } });
ok(!other422.isPagingLimit, 'CONTROL an unrelated 422 is not misclassified');
ok(new ClioApiError('x', { status: 429 }).isRateLimited, '429 is rate limited');
ok(new ClioApiError('x', { status: 401 }).isAuthFailure, '401 is an auth failure');
ok(!new ClioApiError('x', { status: 500 }).isRateLimited, 'CONTROL 500 is not rate limited');

report('client');
