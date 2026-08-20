import { createServer } from 'node:http';
import { appendFileSync, mkdirSync } from 'node:fs';
import { loadConfig } from './lib/config.mjs';
import {
  handleEvent,
  isHandshake,
  handshakeResponse,
  MemoryIdempotencyStore,
  computeSignature,
  DEFAULT_SECRET_HEADER,
  DEFAULT_SIGNATURE_HEADER,
} from './lib/webhook.mjs';

// Webhook receiver, run locally and exposed publicly through a tunnel.
//
// It logs EVERY inbound header verbatim to tests/captures/. That is the whole
// point of running it: the signature and handshake header names in webhook.mjs
// came from a third-party guide because Clio's own webhooks doc returns 404, and
// a header name read in a blog post is not a header name observed on the wire.
// Whatever this captures becomes the sourced truth.
//
// The handshake secret is printed and persisted because it is the HMAC key for
// every later delivery, and Clio sends it exactly once.

const config = loadConfig();
const PORT = Number(process.env.PORT || 3000);
const CAPTURES = 'tests/captures';
mkdirSync(CAPTURES, { recursive: true });

const store = new MemoryIdempotencyStore({ maxEntries: 5000 });
let handshakeSecret = process.env.CLIO_HOOK_SECRET || null;
let n = 0;

function capture(kind, req, rawBody) {
  n += 1;
  const record = {
    n,
    kind,
    at: new Date().toISOString(),
    method: req.method,
    url: req.url,
    headers: req.headers, // verbatim, unfiltered: the point of the exercise
    body: rawBody,
  };
  appendFileSync(`${CAPTURES}/webhook-log.jsonl`, `${JSON.stringify(record)}\n`);
  console.log(`\n--- inbound #${n} (${kind}) ${req.method} ${req.url}`);
  for (const [k, v] of Object.entries(req.headers)) {
    // Flag anything that looks like it carries a secret or a signature, since
    // those are the names being verified.
    const notable = /hook|signature|sign|secret|clio|hmac|timestamp|delivery|event/i.test(k);
    console.log(`  ${notable ? '*' : ' '} ${k}: ${String(v).slice(0, 160)}`);
  }
  if (rawBody) console.log(`  body: ${rawBody.slice(0, 600)}`);
  return record;
}

const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    // Keep the raw bytes. Parsing and re-serializing would change the digest
    // and make every signature check fail for a misleading reason.
    const rawBody = Buffer.concat(chunks).toString('utf8');

    if (req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('clio-matter-bridge webhook receiver: up\n');
      return;
    }

    if (isHandshake(req.headers)) {
      capture('handshake', req, rawBody);
      const hs = handshakeResponse(req.headers);
      handshakeSecret = hs.secret;
      appendFileSync(`${CAPTURES}/handshake-secret.txt`, `${new Date().toISOString()} ${hs.secret}\n`);
      console.log(`  HANDSHAKE secret captured (${hs.secret.length} chars), echoing it back`);
      res.writeHead(hs.status, hs.headers);
      res.end();
      return;
    }

    const record = capture('delivery', req, rawBody);

    if (!handshakeSecret) {
      // Still answer 200. A non-2xx here makes Clio retry and, on repeated
      // failure, disable the subscription, which would cost another handshake.
      console.log('  no handshake secret known yet, cannot verify; accepting to avoid a retry storm');
      res.writeHead(200).end();
      return;
    }

    // Report which header, if any, actually matches an HMAC of the raw body.
    // This is how the real signature header name gets identified rather than
    // assumed.
    const expected = computeSignature(rawBody, handshakeSecret);
    const matches = Object.entries(req.headers).filter(([, v]) =>
      typeof v === 'string' && v.toLowerCase().includes(expected.toLowerCase())
    );
    console.log(
      matches.length
        ? `  SIGNATURE MATCHED header(s): ${matches.map(([k]) => k).join(', ')}`
        : `  no header matched HMAC-SHA256(raw body, handshake secret). expected=${expected.slice(0, 16)}...`
    );

    try {
      const result = await handleEvent({
        rawBody,
        headers: req.headers,
        secret: handshakeSecret,
        store,
        requireTimestamp: false, // unknown payload shape until observed
        signatureHeader: process.env.CLIO_SIGNATURE_HEADER || DEFAULT_SIGNATURE_HEADER,
        handlers: {
          '*': async (payload) => {
            console.log(`  dispatched: ${payload.model ?? '?'}.${payload.event ?? '?'}`);
            return 'logged';
          },
        },
      });
      console.log(`  handleEvent -> ${JSON.stringify(result)}`);
    } catch (err) {
      console.log(`  handleEvent threw: ${err.message}`);
    }
    res.writeHead(200).end();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`clio webhook receiver on :${PORT}`);
  console.log(`captures -> ${CAPTURES}/webhook-log.jsonl`);
  console.log(`watching for '${DEFAULT_SECRET_HEADER}' (handshake) and '${DEFAULT_SIGNATURE_HEADER}' (deliveries)`);
  console.log('every inbound header is logged verbatim; * marks candidates\n');
});
