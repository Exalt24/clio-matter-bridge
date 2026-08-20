import { readFileSync } from 'node:fs';
import { ok, eq, report } from './_assert.mjs';
import {
  computeSignature,
  eventId,
  eventName,
  isHandshake,
  handshakeResponse,
  handleEvent,
  MemoryIdempotencyStore,
  DEFAULT_SIGNATURE_HEADER,
} from '../src/lib/webhook.mjs';

// Tests against the EXACT bytes Clio sent to a deployed receiver on 2026-08-20.
// These are the tests that matter most, because the hand-written suite encoded
// what the documentation and a third-party guide implied, and three of those
// assumptions were wrong. A fixture captured from the wire cannot be wrong about
// what the wire looks like.

const read = (f) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url), 'utf8').trim();
const created = read('clio-delivery-created.json');
const updated = read('clio-delivery-updated.json');
const handshakeBody = read('clio-handshake.json');

// NOT the real subscription secret. The real one was deliberately removed before
// this repo was published: it adds nothing here, because every signature in this
// file is computed AND verified locally, so any string works. Publishing a live
// webhook secret would be a real leak in exchange for zero test value.
const SECRET = 'placeholder-handshake-secret-not-the-real-one';

// ---------- shape of a real delivery ----------
const p = JSON.parse(created);
eq(eventName(p), 'created', 'event name is read from meta.event, where Clio actually puts it');
ok(p.event === undefined, 'confirms there is NO top-level event field, as measured');
ok(p.model === undefined, 'confirms there is NO model field in the payload, as measured');
ok(p.timestamp === undefined, 'confirms there is NO timestamp in the payload, as measured');
ok(p.meta?.webhook_id === 4783872, 'delivery names the subscription it belongs to');
ok(typeof p.data?.etag === 'string', 'delivery carries an etag on the record');
eq(p.data.id, 1925315577, 'delivery carries the record id');

// ---------- handshake ----------
ok(isHandshake({ 'x-hook-secret': SECRET }), 'the real handshake header name is recognised');
eq(handshakeResponse({ 'x-hook-secret': SECRET }).headers['x-hook-secret'], SECRET, 'secret echoed verbatim');
const hb = JSON.parse(handshakeBody);
ok(typeof hb.data?.webhook_id === 'number', 'handshake body identifies the subscription being verified');

// ---------- idempotency at the right granularity ----------
const idCreated = eventId(JSON.parse(created), created);
const idUpdated = eventId(JSON.parse(updated), updated);
ok(idCreated.startsWith('etag:'), 'idempotency key derives from the etag');
ok(
  idCreated !== idUpdated,
  'created and updated on the SAME record produce different keys, so a real update is not swallowed as a duplicate'
);
eq(eventId(JSON.parse(created), created), idCreated, 'the key is deterministic for identical bytes');

// ---------- signature verification over the real bytes ----------
const sigCreated = computeSignature(created, SECRET);
eq(sigCreated.length, 64, 'signature is a 64-char hex digest, matching the header format observed');
const store = new MemoryIdempotencyStore({ maxEntries: 50 });

let seen = [];
let r = await handleEvent({
  rawBody: created,
  headers: { [DEFAULT_SIGNATURE_HEADER]: sigCreated },
  secret: SECRET,
  store,
  handlers: { created: async (pl) => { seen.push(pl.data.id); return 'ok'; } },
});
eq(r.outcome, 'accepted', 'CONTROL a real captured delivery is accepted');
eq(r.dispatched, true, 'handler registered under the bare event name is dispatched');
eq(r.event, 'created', 'dispatch key is the bare event name, since there is no model');
eq(seen[0], 1925315577, 'handler saw the real record id');

// The default must not require a timestamp, because no real delivery has one.
// If this regresses, every genuine Clio event is rejected.
r = await handleEvent({
  rawBody: created,
  headers: { [DEFAULT_SIGNATURE_HEADER]: sigCreated },
  secret: SECRET,
  store: new MemoryIdempotencyStore({ maxEntries: 5 }),
});
ok(r.outcome !== 'rejected', 'a timestampless real delivery is NOT rejected by default');
ok(r.reason !== 'missing_timestamp', 'specifically not rejected for a missing timestamp');

// Redelivery of the same bytes is a duplicate; the genuine update is not.
r = await handleEvent({
  rawBody: created,
  headers: { [DEFAULT_SIGNATURE_HEADER]: sigCreated },
  secret: SECRET,
  store,
});
eq(r.outcome, 'duplicate', 'redelivery of the identical event is suppressed');
r = await handleEvent({
  rawBody: updated,
  headers: { [DEFAULT_SIGNATURE_HEADER]: computeSignature(updated, SECRET) },
  secret: SECRET,
  store,
});
eq(r.outcome, 'accepted', 'the genuine update on the same record still gets through');

// Wrong secret must fail on real bytes too, not only on synthetic ones.
r = await handleEvent({
  rawBody: created,
  headers: { [DEFAULT_SIGNATURE_HEADER]: computeSignature(created, 'not-the-secret') },
  secret: SECRET,
  store: new MemoryIdempotencyStore({ maxEntries: 5 }),
});
eq(r.reason, 'bad_signature', 'a forged signature over real bytes is rejected');

// A single altered byte must break the digest.
const tampered = created.replace('1925315577', '1925315578');
ok(tampered !== created, 'CONTROL the tampered body really differs');
r = await handleEvent({
  rawBody: tampered,
  headers: { [DEFAULT_SIGNATURE_HEADER]: sigCreated },
  secret: SECRET,
  store: new MemoryIdempotencyStore({ maxEntries: 5 }),
});
eq(r.reason, 'bad_signature', 'changing the record id invalidates the signature');

report('captured');
