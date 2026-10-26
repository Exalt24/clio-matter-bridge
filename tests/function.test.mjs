// The deployed function in api/clio-webhook.js is an evidence logger. This suite
// pins what it must never write to the log stream (a secret or a signature in the
// clear) and what it must keep doing (echo the handshake, answer 200).
import { EventEmitter } from 'node:events';
import handler, { fingerprint } from '../api/clio-webhook.js';
import { ok, eq, report } from './_assert.mjs';

const SECRET = 'hs_9f3c2a77d1e04b6c8a52';
const SIGNATURE = 'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00';

async function call({ method = 'POST', headers = {}, body = '' }) {
  const req = new EventEmitter();
  req.method = method;
  req.headers = headers;
  const res = {
    statusCode: null,
    headers: {},
    body: null,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.statusCode = c; return this; },
    send(b) { this.body = b; },
    end() {},
  };
  const lines = [];
  const original = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  try {
    const done = handler(req, res);
    setImmediate(() => { req.emit('data', Buffer.from(body)); req.emit('end'); });
    await done;
  } finally {
    console.log = original;
  }
  return { res, log: lines.join('\n') };
}

// CONTROL: a plain delivery is answered 200 and its ordinary headers are logged
// as received, so the redaction below cannot be a function that logs nothing.
let r = await call({ headers: { 'x-clio-event': 'matter.created', 'content-type': 'application/json' }, body: '{"id":1}' });
eq(r.res.statusCode, 200, 'CONTROL a delivery is answered 200');
ok(r.log.includes('matter.created'), 'CONTROL an ordinary notable header is logged as received');
ok(r.log.includes('CLIO_INBOUND'), 'CONTROL the inbound line is written');

// The handshake secret is echoed back (that is the protocol) and stays out of the log by default.
r = await call({ headers: { 'x-hook-secret': SECRET }, body: '' });
eq(r.res.statusCode, 200, 'the handshake is answered 200');
eq(r.res.headers['x-hook-secret'], SECRET, 'the handshake secret is echoed back to Clio');
ok(!r.log.includes(SECRET), 'the handshake secret is not in the log by default (neither the notable headers nor the handshake line)');
ok(r.log.includes(fingerprint(SECRET)), 'the log carries a length and hash fingerprint instead');

// A signature header value is not written in the clear either.
r = await call({ headers: { 'x-hook-signature': SIGNATURE, 'x-clio-event': 'matter.created' }, body: '{"id":2}' });
ok(!r.log.includes(SIGNATURE), 'a signature header value is not in the log');
ok(r.log.includes('x-hook-signature'), 'the signature header NAME is still logged, which is the evidence the function exists for');

// The deliberate opt-in still works, so the owner can read the secret once.
process.env.CLIO_LOG_HANDSHAKE_SECRET = '1';
r = await call({ headers: { 'x-hook-secret': SECRET }, body: '' });
ok(r.log.includes(`CLIO_HANDSHAKE_SECRET ${SECRET}`), 'with CLIO_LOG_HANDSHAKE_SECRET=1 the handshake line carries the secret');
delete process.env.CLIO_LOG_HANDSHAKE_SECRET;

eq(fingerprint('abc'), fingerprint('abc'), 'a fingerprint is stable');
ok(fingerprint('abc') !== fingerprint('abd'), 'a fingerprint differs for a different value');

report('function');
