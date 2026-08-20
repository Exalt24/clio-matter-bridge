import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';

// Clio Manage OAuth 2.0, authorization-code grant.
// Access tokens live 30 days; refresh tokens do not expire.
// Source: docs.developers.clio.com/api-docs/clio-manage/authorization/

// Refresh this far before the recorded expiry rather than waiting for a 401.
// A 30-day token means a clock-skewed or long-idle worker is the realistic
// failure mode, not second-level precision.
export const REFRESH_SKEW_MS = 5 * 60 * 1000;

export function createState() {
  return randomBytes(32).toString('base64url');
}

// CSRF defence for the redirect. Constant-time so a wrong state cannot be
// discovered by timing, and length-checked first because timingSafeEqual
// throws on a length mismatch instead of returning false.
export function verifyState(expected, received) {
  if (typeof expected !== 'string' || typeof received !== 'string') return false;
  if (expected.length === 0 || expected.length !== received.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}

export function buildAuthorizeUrl({ region, clientId, redirectUri, state, redirectOnDecline = true }) {
  const url = new URL(region.authorizeUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  if (state) url.searchParams.set('state', state);
  // Without this, a user who clicks Decline is left on a Clio page with no way
  // back to the app, so the app never learns the flow ended.
  if (redirectOnDecline) url.searchParams.set('redirect_on_decline', 'true');
  return url.toString();
}

export class ClioAuthError extends Error {
  constructor(message, { status, body, kind } = {}) {
    super(message);
    this.name = 'ClioAuthError';
    this.status = status;
    this.body = body;
    this.kind = kind || 'unknown';
  }
}

function classifyTokenError(status, body) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body || {});
  if (/invalid_client/i.test(raw)) return 'invalid_client';
  if (/invalid_grant/i.test(raw)) return 'invalid_grant';
  if (/redirect_uri/i.test(raw)) return 'redirect_uri_mismatch';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'server_error';
  return 'unknown';
}

async function postForm(url, params, { fetchImpl = fetch } = {}) {
  const body = new URLSearchParams(params).toString();
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body,
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { raw: text };
  }
  if (!res.ok) {
    const kind = classifyTokenError(res.status, text);
    throw new ClioAuthError(`Clio token endpoint returned ${res.status} (${kind})`, {
      status: res.status,
      body: parsed,
      kind,
    });
  }
  return parsed;
}

export function normalizeTokenResponse(raw, now = Date.now()) {
  if (!raw || !raw.access_token) {
    throw new ClioAuthError('Token response contained no access_token', {
      body: raw,
      kind: 'malformed',
    });
  }
  // Clio returns expires_in seconds. Record an absolute instant instead, so a
  // token loaded from disk days later is still evaluated correctly.
  const expiresInSec = Number(raw.expires_in);
  const expiresAt = Number.isFinite(expiresInSec) && expiresInSec > 0
    ? now + expiresInSec * 1000
    : null;
  return {
    accessToken: raw.access_token,
    refreshToken: raw.refresh_token || null,
    tokenType: raw.token_type || 'Bearer',
    expiresAt,
    obtainedAt: now,
  };
}

export async function exchangeCode({ region, clientId, clientSecret, redirectUri, code }, opts = {}) {
  const raw = await postForm(
    region.tokenUrl,
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
    },
    opts
  );
  return normalizeTokenResponse(raw, opts.now ?? Date.now());
}

export async function refreshAccessToken({ region, clientId, clientSecret, refreshToken }, opts = {}) {
  if (!refreshToken) {
    throw new ClioAuthError('No refresh token available; re-authorization required', {
      kind: 'no_refresh_token',
    });
  }
  const raw = await postForm(
    region.tokenUrl,
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    },
    opts
  );
  const next = normalizeTokenResponse(raw, opts.now ?? Date.now());
  // Clio may omit refresh_token on a refresh response. Dropping it here would
  // silently strip the only credential that survives access-token expiry.
  if (!next.refreshToken) next.refreshToken = refreshToken;
  return next;
}

export function isExpired(token, now = Date.now(), skewMs = REFRESH_SKEW_MS) {
  if (!token || !token.accessToken) return true;
  if (token.expiresAt == null) return false; // no expiry recorded: trust until a 401 says otherwise
  return now >= token.expiresAt - skewMs;
}

export function saveTokens(path, token) {
  writeFileSync(path, JSON.stringify(token, null, 2), { encoding: 'utf8', mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Windows ignores POSIX modes. The .gitignore entry is the real guard.
  }
}

export function loadTokens(path) {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

// Single place that turns "some token on disk" into "a usable access token",
// refreshing and persisting when needed.
export async function getAccessToken(config, opts = {}) {
  const now = opts.now ?? Date.now();
  let token = opts.token ?? loadTokens(config.tokenPath);
  if (!token) {
    throw new ClioAuthError('No stored token. Run `npm run auth` to authorize.', {
      kind: 'not_authorized',
    });
  }
  if (isExpired(token, now)) {
    token = await refreshAccessToken(
      {
        region: config.region,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        refreshToken: token.refreshToken,
      },
      opts
    );
    if (!opts.skipPersist) saveTokens(config.tokenPath, token);
  }
  return token;
}
