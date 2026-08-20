import { ok, eq, throws, report } from './_assert.mjs';
import {
  computeSignature,
  verifySignature,
  checkTimestamp,
  MemoryIdempotencyStore,
  eventId,
  isHandshake,
  handshakeResponse,
  handleEvent,
  WebhookRejected,
  DEFAULT_SIGNATURE_HEADER,
  DEFAULT_SECRET_HEADER,
} from '../src/lib/webhook.mjs';

const SECRET = 'shhh-this-is-the-handshake-secret';
const NOW = 1_700_000_000_000;

const body = (over = {}) =>
  JSON.stringify({
    id: 'evt_1',
    event: 'created',
    model: 'matter',
    timestamp: new Date(NOW).toISOString(),
    data: { id: 42, display_number: '00001-Smith' },
    ...over,
  });

const signed = (raw, secret = SECRET, header = DEFAULT_SIGNATURE_HEADER) => ({
  [header]: computeSignature(raw, secret),
});

// ---------- signature ----------
const raw = body();
ok(verifySignature(raw, SECRET, computeSignature(raw, SECRET)), 'CONTROL valid signature accepted');
ok(!verifySignature(raw, SECRET, computeSignature(raw, 'wrong-secret')), 'wrong secret rejected');
ok(!verifySignature(`${raw} `, SECRET, computeSignature(raw, SECRET)), 'tampered body rejected');
ok(!verifySignature(raw, SECRET, ''), 'empty signature rejected');
ok(!verifySignature(raw, SECRET, null), 'null signature rejected');
ok(!verifySignature(raw, SECRET, 'deadbeef'), 'short garbage rejected without throwing');
ok(verifySignature(raw, SECRET, `sha256=${computeSignature(raw, SECRET)}`), 'algorithm-prefixed form accepted');
eq(computeSignature(raw, SECRET).length, 64, 'hex sha256 digest is 64 chars');

// The defect this whole design exists to prevent: signing a re-serialized copy
// of the parsed object instead of the bytes that arrived. Key order and spacing
// differ, so the digest differs, and the check fails for a reason that looks
// like a wrong secret.
const reserialized = JSON.stringify(JSON.parse(raw), ['event', 'model', 'id']);
ok(reserialized !== raw, 'CONTROL re-serialized body really does differ from the raw bytes');
ok(
  !verifySignature(reserialized, SECRET, computeSignature(raw, SECRET)),
  're-serialized body fails a signature computed over the raw bytes'
);

// Buffer input must behave identically to string input, since a real server
// hands over bytes.
eq(
  computeSignature(Buffer.from(raw), SECRET),
  computeSignature(raw, SECRET),
  'Buffer and string bodies produce the same digest'
);

// ---------- timestamp / replay ----------
eq(checkTimestamp(new Date(NOW).toISOString(), { now: NOW }), NOW, 'CONTROL current timestamp accepted');
eq(checkTimestamp(NOW - 60_000, { now: NOW }), NOW - 60_000, 'CONTROL numeric ms timestamp accepted');
ok(!!checkTimestamp(new Date(NOW - 4 * 60_000).toISOString(), { now: NOW }), 'CONTROL inside tolerance accepted');
await throws(
  () => checkTimestamp(new Date(NOW - 10 * 60_000).toISOString(), { now: NOW }),
  /timestamp_too_old/,
  'old timestamp rejected'
);
await throws(
  () => checkTimestamp(new Date(NOW + 10 * 60_000).toISOString(), { now: NOW }),
  /timestamp_in_future/,
  'future timestamp rejected, not just old ones'
);
await throws(() => checkTimestamp(null, { now: NOW }), /missing_timestamp/, 'null timestamp rejected');
await throws(() => checkTimestamp('', { now: NOW }), /missing_timestamp/, 'empty timestamp rejected');
await throws(() => checkTimestamp('not-a-date', { now: NOW }), /unparseable_timestamp/, 'garbage timestamp rejected');
// The reason code, not the message, is what callers branch on.
try {
  checkTimestamp('nope', { now: NOW });
} catch (err) {
  ok(err instanceof WebhookRejected, 'throws the typed error');
  eq(err.reason, 'unparseable_timestamp', 'reason is machine-readable');
}

// ---------- idempotency store ----------
const store = new MemoryIdempotencyStore({ maxEntries: 3 });
ok(store.add('a'), 'CONTROL first add returns true');
ok(!store.add('a'), 'second add of the same id returns false');
ok(store.has('a'), 'has() sees a recorded id');
ok(!store.has('zzz'), 'has() does not see an unrecorded id');
store.add('b');
store.add('c');
eq(store.size, 3, 'store holds up to maxEntries');
store.add('d');
eq(store.size, 3, 'store does not grow past maxEntries');
ok(!store.has('a'), 'oldest entry evicted first (FIFO)');
ok(store.has('d'), 'newest entry retained');
await throws(() => new MemoryIdempotencyStore({ maxEntries: 0 }), /positive integer/, 'zero maxEntries rejected');
await throws(() => new MemoryIdempotencyStore({ maxEntries: 1.5 }), /positive integer/, 'fractional maxEntries rejected');

// ---------- event id derivation ----------
eq(eventId({ id: 'evt_9' }, ''), 'evt_9', 'explicit id preferred');
eq(eventId({ event_id: 'evt_8' }, ''), 'evt_8', 'event_id accepted');
eq(eventId({ meta: { event_id: 'evt_7' } }, ''), 'evt_7', 'nested meta event_id accepted');
eq(
  eventId({ event: 'created', model: 'matter', data: { id: 5 }, timestamp: 't' }, ''),
  'derived:created:matter:5:t',
  'falls back to a deterministic fingerprint'
);
// Determinism is the whole point: a random fallback would make every redelivery
// look like a new event and defeat idempotency entirely.
eq(eventId({}, 'abc'), eventId({}, 'abc'), 'body fallback is deterministic for identical bodies');
ok(eventId({}, 'abc') !== eventId({}, 'abd'), 'body fallback differs for different bodies');

// ---------- handshake ----------
ok(isHandshake({ [DEFAULT_SECRET_HEADER]: 'sekret' }), 'CONTROL handshake detected');
ok(isHandshake({ 'X-Hook-Secret': 'sekret' }), 'header match is case-insensitive');
ok(!isHandshake({ [DEFAULT_SIGNATURE_HEADER]: 'sig' }), 'a signed delivery is not a handshake');
ok(!isHandshake({}), 'no headers is not a handshake');
ok(!isHandshake({ [DEFAULT_SECRET_HEADER]: '' }), 'empty secret header is not a handshake');
const hs = handshakeResponse({ [DEFAULT_SECRET_HEADER]: 'sekret' });
eq(hs.status, 200, 'handshake answers 200');
eq(hs.headers[DEFAULT_SECRET_HEADER], 'sekret', 'handshake echoes the secret back verbatim');
await throws(() => handshakeResponse({}), /not_a_handshake/, 'handshake response refuses a non-handshake');

// ---------- handleEvent ----------
const fresh = () => new MemoryIdempotencyStore({ maxEntries: 100 });

let r = await handleEvent({ rawBody: raw, headers: signed(raw), secret: SECRET, store: fresh(), now: NOW });
eq(r.outcome, 'accepted', 'CONTROL well-formed signed event accepted');
eq(r.id, 'evt_1', 'event id surfaced');
eq(r.dispatched, false, 'no handler registered means dispatched=false, not an error');

r = await handleEvent({ rawBody: raw, headers: {}, secret: SECRET, store: fresh(), now: NOW });
eq(r.outcome, 'rejected', 'missing signature header rejected');
eq(r.reason, 'missing_signature', 'reason names the missing header');

r = await handleEvent({
  rawBody: raw,
  headers: signed(raw, 'other-secret'),
  secret: SECRET,
  store: fresh(),
  now: NOW,
});
eq(r.reason, 'bad_signature', 'signature from the wrong secret rejected');

r = await handleEvent({ rawBody: 'not json', headers: signed('not json'), secret: SECRET, store: fresh(), now: NOW });
eq(r.reason, 'unparseable_body', 'unparseable body rejected after the signature passes');

// requireTimestamp is OPT-IN, because a real Clio delivery carries no timestamp
// at all (measured 2026-08-20) and defaulting it on rejected every genuine
// event. Senders that DO provide one still get replay protection on request.
const oldRaw = body({ timestamp: new Date(NOW - 10 * 60_000).toISOString() });
r = await handleEvent({
  rawBody: oldRaw,
  headers: signed(oldRaw),
  secret: SECRET,
  store: fresh(),
  now: NOW,
  requireTimestamp: true,
});
eq(r.reason, 'timestamp_too_old', 'replayed old event rejected when the guard is enabled');
// Pin the default, so re-enabling it by accident is caught here rather than in
// production by every Clio event failing.
r = await handleEvent({ rawBody: oldRaw, headers: signed(oldRaw), secret: SECRET, store: fresh(), now: NOW });
ok(r.outcome !== 'rejected', 'DEFAULT does not require a timestamp, since real deliveries have none');

// Duplicate suppression, and the ordering guarantee that goes with it.
const shared = fresh();
r = await handleEvent({ rawBody: raw, headers: signed(raw), secret: SECRET, store: shared, now: NOW });
eq(r.outcome, 'accepted', 'CONTROL first delivery accepted');
r = await handleEvent({ rawBody: raw, headers: signed(raw), secret: SECRET, store: shared, now: NOW });
eq(r.outcome, 'duplicate', 'identical redelivery reported as duplicate');
const other = body({ id: 'evt_2' });
r = await handleEvent({ rawBody: other, headers: signed(other), secret: SECRET, store: shared, now: NOW });
eq(r.outcome, 'accepted', 'a different event id is still accepted');

// An unauthenticated request must not be able to reserve an id and thereby
// suppress the real event that follows.
const poison = fresh();
await handleEvent({ rawBody: raw, headers: signed(raw, 'attacker'), secret: SECRET, store: poison, now: NOW });
eq(poison.size, 0, 'a rejected request records nothing, so the cache cannot be poisoned');
r = await handleEvent({ rawBody: raw, headers: signed(raw), secret: SECRET, store: poison, now: NOW });
eq(r.outcome, 'accepted', 'the genuine event still lands after a forged attempt');

// Dispatch
let seen = null;
r = await handleEvent({
  rawBody: raw,
  headers: signed(raw),
  secret: SECRET,
  store: fresh(),
  now: NOW,
  handlers: { 'matter.created': async (p) => { seen = p.data.id; return 'handled'; } },
});
eq(r.dispatched, true, 'matching handler dispatched');
eq(r.event, 'matter.created', 'event key is model.event');
eq(seen, 42, 'handler received the parsed payload');
eq(r.result, 'handled', 'handler return value surfaced');

r = await handleEvent({
  rawBody: raw,
  headers: signed(raw),
  secret: SECRET,
  store: fresh(),
  now: NOW,
  handlers: { '*': async () => 'wildcard' },
});
eq(r.result, 'wildcard', 'wildcard handler used when no exact match');

const unknown = body({ id: 'evt_3', model: 'invoice', event: 'destroyed' });
r = await handleEvent({
  rawBody: unknown,
  headers: signed(unknown),
  secret: SECRET,
  store: fresh(),
  now: NOW,
  handlers: { 'matter.created': async () => 'nope' },
});
eq(r.outcome, 'accepted', 'unknown event type does not throw');
eq(r.dispatched, false, 'unknown event type is not dispatched');

// A throwing handler must surface. Swallowing it would return 200 to Clio,
// cancelling its retry and losing the event permanently.
await throws(
  () =>
    handleEvent({
      rawBody: raw,
      headers: signed(raw),
      secret: SECRET,
      store: fresh(),
      now: NOW,
      handlers: { 'matter.created': async () => { throw new Error('downstream is down'); } },
    }),
  /downstream is down/,
  'handler errors propagate rather than being swallowed into a 200'
);

// Guard rails on the API itself.
await throws(
  () => handleEvent({ rawBody: JSON.parse(raw), headers: signed(raw), secret: SECRET }),
  /must be a string or Buffer/,
  'passing a parsed object instead of raw bytes is refused outright'
);
await throws(
  () => handleEvent({ rawBody: raw, headers: signed(raw), secret: '' }),
  /secret is required/,
  'missing secret refused'
);

// Configurable header name, since the name comes from a secondary source and
// may be wrong until confirmed against a real delivery.
r = await handleEvent({
  rawBody: raw,
  headers: signed(raw, SECRET, 'x-custom-sig'),
  secret: SECRET,
  store: fresh(),
  now: NOW,
  signatureHeader: 'x-custom-sig',
});
eq(r.outcome, 'accepted', 'signature header name is configurable');

// Timestamp check can be waived for a sender that does not include one, but
// waiving it must not accidentally waive the signature too.
const noTs = JSON.stringify({ id: 'evt_4', event: 'created', model: 'matter', data: { id: 1 } });
r = await handleEvent({
  rawBody: noTs,
  headers: signed(noTs),
  secret: SECRET,
  store: fresh(),
  now: NOW,
  requireTimestamp: false,
});
eq(r.outcome, 'accepted', 'timestamp requirement can be waived');
r = await handleEvent({
  rawBody: noTs,
  headers: signed(noTs, 'wrong'),
  secret: SECRET,
  store: fresh(),
  now: NOW,
  requireTimestamp: false,
});
eq(r.reason, 'bad_signature', 'waiving the timestamp does not waive the signature');

report('webhook');
