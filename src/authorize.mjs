import { createServer } from 'node:http';
import { loadConfig } from './lib/config.mjs';
import {
  buildAuthorizeUrl,
  createState,
  verifyState,
  exchangeCode,
  saveTokens,
} from './lib/clio-oauth.mjs';

// One-shot authorization-code flow against a real Clio account.
// Binds 127.0.0.1 (not localhost) because the developer portal states redirect
// URIs "must use https or http://127.0.0.1, not localhost".

const config = loadConfig();
const state = createState();
const redirect = new URL(config.redirectUri);
const port = Number(redirect.port || 80);

const authorizeUrl = buildAuthorizeUrl({
  region: config.region,
  clientId: config.clientId,
  redirectUri: config.redirectUri,
  state,
});

const html = (title, detail) =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
  `<body style="font:16px system-ui;padding:3rem;max-width:40rem">` +
  `<h1 style="font-size:1.4rem">${title}</h1><p>${detail}</p></body>`;

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${redirect.hostname}:${port}`);
  if (url.pathname !== redirect.pathname) {
    res.writeHead(404).end('not found');
    return;
  }

  const error = url.searchParams.get('error');
  if (error) {
    // Reached because redirect_on_decline=true is set. Without it a declining
    // user is stranded on Clio and the app never learns the flow ended.
    res.writeHead(400, { 'content-type': 'text/html' });
    res.end(html('Authorization declined', `Clio returned: <code>${error}</code>`));
    console.error(`\nAuthorization declined by user: ${error}`);
    server.close();
    process.exitCode = 1;
    return;
  }

  const returnedState = url.searchParams.get('state') || '';
  if (!verifyState(state, returnedState)) {
    res.writeHead(400, { 'content-type': 'text/html' });
    res.end(html('State mismatch', 'The state parameter did not match. Request rejected.'));
    console.error('\nState mismatch. Possible CSRF, or a stale callback from an earlier run.');
    server.close();
    process.exitCode = 1;
    return;
  }

  const code = url.searchParams.get('code');
  if (!code) {
    res.writeHead(400, { 'content-type': 'text/html' });
    res.end(html('No code', 'Clio redirected without an authorization code.'));
    server.close();
    process.exitCode = 1;
    return;
  }

  try {
    const token = await exchangeCode({
      region: config.region,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      code,
    });
    saveTokens(config.tokenPath, token);
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html('Connected', 'Token stored. You can close this tab.'));
    const days = token.expiresAt
      ? ((token.expiresAt - Date.now()) / 86400000).toFixed(1)
      : 'unknown';
    console.log('\nAuthorized.');
    console.log(`  access token   : stored in ${config.tokenPath}`);
    console.log(`  expires in     : ${days} days`);
    console.log(`  refresh token  : ${token.refreshToken ? 'present' : 'MISSING'}`);
  } catch (err) {
    res.writeHead(500, { 'content-type': 'text/html' });
    res.end(html('Token exchange failed', String(err.message)));
    console.error(`\nToken exchange failed: ${err.message}`);
    if (err.kind === 'invalid_client') {
      console.error('  invalid_client usually means the client id and secret are swapped.');
    }
    if (err.kind === 'redirect_uri_mismatch') {
      console.error(`  the app must list exactly: ${config.redirectUri}`);
    }
    if (err.body) console.error('  body:', JSON.stringify(err.body));
    process.exitCode = 1;
  } finally {
    server.close();
  }
});

server.listen(port, redirect.hostname, () => {
  console.log(`Listening on ${redirect.origin}${redirect.pathname}`);
  console.log(`Region: ${config.region.key} (${config.region.apiBase})`);
  console.log('\nOpen this URL in a browser signed in to Clio, then click Allow:\n');
  console.log(authorizeUrl);
  console.log('');
});
