import { createHmac, timingSafeEqual } from 'node:crypto';

// Inbound Clio Manage webhook handling. Pure functions only; the HTTP server
// lives in src/server.mjs so this file stays unit-testable.
//
// THE CONTRACT, and where each part came from, because the provenance differs
// and that matters for how much to trust it:
//
//  MEASURED against a live account 2026-08-20 (trustworthy):
//   - POST /webhooks needs a `data` wrapper, else 400 ParameterMissing.
//   - `model` is required, else 422 RecordInvalid "Model can't be blank".
//   - Event names are BARE VERBS with a separate model. "matter.created" is
//     rejected with 422 ArgumentError; {model:'matter', events:['created']} is
//     accepted.
//   - A new subscription is created with status "pending", not active.
//
//  READ from a third-party guide and Clio's help centre, NOT primary docs
//  (docs.developers.clio.com/api-docs/clio-manage/webhooks/ returns 404), so
//  the header NAMES below are configurable and must be confirmed against a real
//  delivery before anyone claims they were observed:
//   - Handshake: Clio POSTs with an X-Hook-Secret header; echo that header back
//     with a 200 to activate the pending subscription.
//   - Deliveries: X-Hook-Signature carries an HMAC-SHA256 of the RAW body keyed
//     on the handshake secret.

export const DEFAULT_SIGNATURE_HEADER = 'x-hook-signature';
export const DEFAULT_SECRET_HEADER = 'x-hook-secret';
export const DEFAULT_TOLERANCE_MS = 5 * 60 * 1000;

export class WebhookRejected extends Error {
  constructor(reason, detail) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = 'WebhookRejected';
    this.reason = reason; // machine-readable; callers switch on this, not the text
  }
}

function headerValue(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === 'function') return headers.get(name);
  const wanted = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === wanted) return v;
  }
  return null;
}

export function computeSignature(rawBody, secret) {
  // rawBody must be the exact bytes received. Re-serializing the parsed JSON
  // changes key order and whitespace, which changes the digest, which is the
  // single most common cause of "my signature check never passes".
  return createHmac('sha256', secret).update(rawBody).digest('hex');
}

export function verifySignature(rawBody, secret, provided) {
  if (typeof provided !== 'string' || provided.length === 0) return false;
  const expected = computeSignature(rawBody, secret);
  // Some senders prefix the algorithm. Accept either form rather than failing
  // on a cosmetic difference.
  const candidate = provided.includes('=') ? provided.slice(provided.indexOf('=') + 1) : provided;
  if (candidate.length !== expected.length) return false; // timingSafeEqual throws on length mismatch
  return timingSafeEqual(Buffer.from(candidate), Buffer.from(expected));
}

// A signature alone does not stop a captured request being replayed later, so
// the payload timestamp is checked against a tolerance in BOTH directions. A
// future timestamp is as suspicious as an old one and usually means clock skew.
export function checkTimestamp(value, { now = Date.now(), toleranceMs = DEFAULT_TOLERANCE_MS } = {}) {
  if (value === null || value === undefined || value === '') {
    throw new WebhookRejected('missing_timestamp');
  }
  const ms = typeof value === 'number' ? value : Date.parse(value);
  if (!Number.isFinite(ms)) throw new WebhookRejected('unparseable_timestamp', String(value));
  const drift = ms - now;
  if (drift > toleranceMs) throw new WebhookRejected('timestamp_in_future', `${Math.round(drift / 1000)}s ahead`);
  if (-drift > toleranceMs) throw new WebhookRejected('timestamp_too_old', `${Math.round(-drift / 1000)}s behind`);
  return ms;
}

// Bounded FIFO. An unbounded Set is a slow memory leak in a long-lived
// receiver, and an unbounded TTL map is the same leak with extra steps. A
// bounded queue trades a theoretical miss on a very old redelivery for a hard
// ceiling, which is the right trade for a duplicate-suppression cache.
export class MemoryIdempotencyStore {
  constructor({ maxEntries = 10000 } = {}) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new TypeError('maxEntries must be a positive integer');
    }
    this.maxEntries = maxEntries;
    this.seen = new Set();
    this.order = [];
  }
  has(id) {
    return this.seen.has(id);
  }
  add(id) {
    if (this.seen.has(id)) return false;
    this.seen.add(id);
    this.order.push(id);
    while (this.order.length > this.maxEntries) {
      this.seen.delete(this.order.shift());
    }
    return true;
  }
  get size() {
    return this.seen.size;
  }
}

// Where the event name actually lives. MEASURED from real deliveries
// 2026-08-20: Clio puts it at `meta.event`, NOT at the top level, and sends NO
// `model` field at all (model is a property of the subscription, not of the
// delivery). The top-level forms are kept as fallbacks so a sender that does
// use them still works.
export function eventName(payload) {
  const p = payload || {};
  return p.meta?.event ?? p.event ?? null;
}

// Clio's own event id if it sends one, else a deterministic fingerprint of the
// parts that identify the occurrence. Falling back to a random id would defeat
// the whole point, since every redelivery would look new.
//
// MEASURED: a real delivery carries no dedicated event id. It carries
// `data.etag`, which CHANGES between versions of the same record (the created
// and updated deliveries for one matter had different etags), so record id plus
// etag identifies a specific version of a specific record. That is exactly the
// granularity idempotency needs: a genuine update must not be swallowed as a
// duplicate of the create, and a redelivery of the same update must be.
export function eventId(payload, rawBody) {
  const p = payload || {};
  const explicit = p.id ?? p.event_id ?? p.meta?.event_id;
  if (explicit !== undefined && explicit !== null && explicit !== '') return String(explicit);
  const etag = p.data?.etag;
  const recordId = p.data?.id;
  if (recordId !== undefined && etag !== undefined) {
    return `etag:${eventName(p) ?? '?'}:${recordId}:${String(etag).replace(/"/g, '')}`;
  }
  const parts = [eventName(p), p.model, recordId, p.timestamp].filter((x) => x !== undefined && x !== null);
  if (parts.length) return `derived:${parts.join(':')}`;
  return `body:${createHmac('sha256', 'idempotency').update(rawBody || '').digest('hex').slice(0, 32)}`;
}

export function isHandshake(headers, { secretHeader = DEFAULT_SECRET_HEADER } = {}) {
  return typeof headerValue(headers, secretHeader) === 'string' && !!headerValue(headers, secretHeader);
}

export function handshakeResponse(headers, { secretHeader = DEFAULT_SECRET_HEADER } = {}) {
  const secret = headerValue(headers, secretHeader);
  if (!secret) throw new WebhookRejected('not_a_handshake');
  // Echoing the header back is what flips the subscription out of "pending".
  return { status: 200, headers: { [secretHeader]: secret }, secret };
}

export async function handleEvent({
  rawBody,
  headers,
  secret,
  store,
  handlers = {},
  now = Date.now(),
  toleranceMs = DEFAULT_TOLERANCE_MS,
  signatureHeader = DEFAULT_SIGNATURE_HEADER,
  // MEASURED 2026-08-20: a real Clio delivery contains NO timestamp anywhere in
  // the payload. Defaulting this to true would therefore reject every genuine
  // delivery with `missing_timestamp`, so the default is false and the guard is
  // opt-in for senders that do provide one. Replay protection for Clio has to
  // come from the idempotency store instead, which is why `store` matters more
  // here than it would elsewhere.
  requireTimestamp = false,
}) {
  if (typeof rawBody !== 'string' && !Buffer.isBuffer(rawBody)) {
    throw new TypeError('rawBody must be a string or Buffer, never a parsed object');
  }
  if (!secret) throw new TypeError('secret is required');

  const provided = headerValue(headers, signatureHeader);
  if (!provided) return { outcome: 'rejected', reason: 'missing_signature' };
  if (!verifySignature(rawBody, secret, provided)) {
    return { outcome: 'rejected', reason: 'bad_signature' };
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString());
  } catch {
    return { outcome: 'rejected', reason: 'unparseable_body' };
  }

  if (requireTimestamp) {
    try {
      checkTimestamp(payload.timestamp ?? payload.meta?.timestamp, { now, toleranceMs });
    } catch (err) {
      if (err instanceof WebhookRejected) return { outcome: 'rejected', reason: err.reason, detail: err.message };
      throw err;
    }
  }

  const id = eventId(payload, rawBody);

  // Idempotency is checked AFTER authentication on purpose: an unauthenticated
  // request must never be able to poison the cache and suppress a real event.
  if (store && store.has(id)) return { outcome: 'duplicate', id };
  if (store) store.add(id);

  // Dispatch key. A real Clio delivery has no `model`, so `model` is accepted
  // from the payload only when a sender provides it, and the bare event name is
  // the normal case. Both `matter.created` and `created` are looked up so a
  // caller can register either.
  const event = eventName(payload);
  const qualified = payload.model && event ? `${payload.model}.${event}` : null;
  const key = qualified ?? event;
  const handler = (qualified && handlers[qualified]) || handlers[key] || handlers['*'];
  if (!handler) return { outcome: 'accepted', id, dispatched: false, event: key };

  // Handler errors propagate. Swallowing them would return 200 to Clio, which
  // cancels its retry, so a transient failure on our side would silently lose
  // the event forever.
  const result = await handler(payload, { id, rawBody });
  return { outcome: 'accepted', id, dispatched: true, event: key, result };
}
