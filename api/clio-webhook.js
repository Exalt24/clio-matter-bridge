import { createHash, createHmac } from 'node:crypto';

// Always-on Clio webhook receiver, deployed as a serverless function.
//
// This is the deployable shape, deliberately not a tunnel to a workstation. A
// tunnelled endpoint dies whenever that machine sleeps, Clio's retries then
// fail, and after repeated failures the subscription is disabled. For a firm's
// intake automation that failure is silent and expensive, so the receiver has
// to live somewhere that is up when nobody is at a desk.
//
// Its first job is evidential: log every inbound header verbatim so the real
// handshake and signature header names are OBSERVED rather than taken from a
// third-party guide, because Clio's own webhooks doc page returns 404.
//
// ESM, not CommonJS: this package sets "type": "module", so a .js file here is
// ESM and `require` is undefined. A CommonJS first draft crashed the function
// with FUNCTION_INVOCATION_FAILED for exactly that reason.

// Disables the platform's automatic JSON body parsing. Parsing and
// re-serializing changes key order and whitespace, so the HMAC over the body no
// longer matches and every signature check fails for a misleading reason.
export const config = { api: { bodyParser: false } };

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// A secret or a signature never goes into the log stream in the clear: the log
// keeps its length and a short hash, which is enough to see that a header
// arrived and whether two deliveries carried the same value. The one exception
// is the handshake secret, which the owner needs once to set CLIO_HOOK_SECRET;
// it is written out only when CLIO_LOG_HANDSHAKE_SECRET=1 is set on purpose.
export function fingerprint(value) {
  const text = Array.isArray(value) ? value.join(',') : String(value);
  return `<redacted length=${text.length} sha256=${createHash('sha256').update(text).digest('hex').slice(0, 8)}>`;
}

const SENSITIVE_HEADER = /secret|sign|hmac|digest|authorization|cookie/i;

function headerValue(headers, name) {
  const wanted = name.toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === wanted) return headers[key];
  }
  return null;
}

export default async function handler(req, res) {
  if (req.method === 'GET') {
    res.status(200).send('clio-matter-bridge webhook receiver: up\n');
    return;
  }

  let raw = '';
  try {
    raw = (await readRaw(req)).toString('utf8');
  } catch {
    // A body that cannot be read is still worth logging as an event.
    raw = '';
  }

  // The evidence. One line of JSON so it is greppable in the log stream.
  const notable = {};
  for (const [k, v] of Object.entries(req.headers || {})) {
    if (/hook|sign|secret|clio|hmac|timestamp|delivery|event|digest/i.test(k)) notable[k] = SENSITIVE_HEADER.test(k) ? fingerprint(v) : v;
  }
  console.log(
    'CLIO_INBOUND ' +
      JSON.stringify({
        at: new Date().toISOString(),
        method: req.method,
        notable_headers: notable,
        all_header_names: Object.keys(req.headers || {}),
        body_bytes: raw.length,
        body: raw.slice(0, 2000),
      })
  );

  // Handshake: Clio sends a one-off secret and expects it echoed back. That is
  // what moves a subscription out of "pending", which was measured directly, a
  // freshly created webhook returns status "pending".
  const handshake = headerValue(req.headers, 'x-hook-secret');
  if (handshake) {
    console.log(
      process.env.CLIO_LOG_HANDSHAKE_SECRET === '1'
        ? `CLIO_HANDSHAKE_SECRET ${handshake}`
        : `CLIO_HANDSHAKE_SECRET ${fingerprint(handshake)}`
    );
    res.setHeader('x-hook-secret', handshake);
    res.status(200).end();
    return;
  }

  // Deliveries. The shared secret arrives only once, at handshake, so in a real
  // deployment it belongs in a secret store; here it comes from an env var set
  // after the handshake has been observed.
  const secret = process.env.CLIO_HOOK_SECRET || '';
  if (secret && raw) {
    const expected = createHmac('sha256', secret).update(raw).digest('hex');
    // Report WHICH header carries the digest rather than assuming its name.
    const matched = Object.entries(req.headers || {})
      .filter(([, v]) => typeof v === 'string' && v.toLowerCase().includes(expected.toLowerCase()))
      .map(([k]) => k);
    console.log(
      matched.length
        ? `CLIO_SIGNATURE_HEADER_IDENTIFIED ${matched.join(',')}`
        : `CLIO_SIGNATURE_NO_MATCH expected_prefix=${expected.slice(0, 16)}`
    );
  }

  // Always 200 on a delivery. A non-2xx makes Clio retry, and a receiver still
  // learning the payload shape should not trigger a retry storm.
  res.status(200).end();
}
