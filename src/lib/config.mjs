import { readFileSync, existsSync } from 'node:fs';
import { resolveRegion } from './regions.mjs';

// Minimal dotenv. Deliberately not a dependency: this repo has zero runtime
// deps so it can be cloned and run without an install step.
export function parseEnvFile(text) {
  const out = {};
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length > 1) ||
      (value.startsWith("'") && value.endsWith("'") && value.length > 1)
    ) {
      value = value.slice(1, -1);
    }
    if (key) out[key] = value;
  }
  return out;
}

export function loadEnv(path = '.env') {
  const fromFile = existsSync(path) ? parseEnvFile(readFileSync(path, 'utf8')) : {};
  // Real environment wins over the file, so CI can override without editing it.
  return { ...fromFile, ...process.env };
}

export function loadConfig(env = loadEnv()) {
  const missing = ['CLIO_CLIENT_ID', 'CLIO_CLIENT_SECRET'].filter((k) => !env[k]);
  if (missing.length) {
    throw new Error(
      `Missing required config: ${missing.join(', ')}. Copy .env.example to .env and fill it in.`
    );
  }
  const region = resolveRegion(env.CLIO_REGION || 'us');
  const redirectUri = env.CLIO_REDIRECT_URI || 'http://127.0.0.1:3000/oauth/callback';
  assertRedirectUri(redirectUri);
  return {
    clientId: env.CLIO_CLIENT_ID,
    clientSecret: env.CLIO_CLIENT_SECRET,
    redirectUri,
    region,
    webhookSecret: env.CLIO_WEBHOOK_SECRET || '',
    groqApiKey: env.GROQ_API_KEY || '',
    tokenPath: env.CLIO_TOKEN_PATH || '.tokens.json',
  };
}

// The developer portal states: "Must use https or http://127.0.0.1, not localhost."
// Checking it here turns a silent mid-flow redirect_uri_mismatch into a startup error.
export function assertRedirectUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error(`CLIO_REDIRECT_URI is not a valid URL: ${uri}`);
  }
  if (parsed.protocol === 'https:') return parsed;
  if (parsed.protocol === 'http:' && parsed.hostname === '127.0.0.1') return parsed;
  if (parsed.protocol === 'http:' && parsed.hostname === 'localhost') {
    throw new Error(
      'Clio rejects "localhost" in redirect URIs. Use http://127.0.0.1 instead ' +
        '(the portal states: must use https or http://127.0.0.1, not localhost).'
    );
  }
  throw new Error(
    `Redirect URI must be https or http://127.0.0.1. Got: ${uri}`
  );
}
