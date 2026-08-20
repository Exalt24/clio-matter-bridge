import { getAccessToken, ClioAuthError } from './clio-oauth.mjs';

// Clio Manage v4 client.
//
// Three platform behaviours drive this file, all of them things that bite in
// production rather than in a first curl:
//
// 1. FIELDS. If you omit the `fields` parameter Clio returns only a minimal
//    default set, so a caller that "worked" in testing silently lacks the
//    columns it needs. There is also a hard 1000-character limit on the
//    parameter; over that the request is rejected outright.
// 2. PAGINATION. Offset paging is capped at 10,000 records (50 pages) and
//    returns a 422 past that. Cursor paging requires order=id(asc) and no
//    offset, and has no ceiling. So cursor is the default here.
// 3. RATE LIMITS. 50 requests/minute at peak. Every response carries
//    X-RateLimit-Limit / -Remaining / -Reset, and a 429 carries Retry-After.
//
// Sources: docs.developers.clio.com/api-docs/clio-manage/fields/,
//          /api-docs/paging/, /api-docs/clio-manage/rate-limits/

export const FIELDS_MAX_LENGTH = 1000;
export const OFFSET_PAGINATION_MAX_RECORDS = 10000;

export class ClioApiError extends Error {
  constructor(message, { status, body, url, retryAfter } = {}) {
    super(message);
    this.name = 'ClioApiError';
    this.status = status;
    this.body = body;
    this.url = url;
    this.retryAfter = retryAfter;
  }
  get isRateLimited() {
    return this.status === 429;
  }
  get isAuthFailure() {
    return this.status === 401;
  }
  // 422 from a paging call is almost always the offset ceiling rather than a
  // malformed request, which is worth saying out loud in the message.
  get isPagingLimit() {
    return this.status === 422 && /offset/i.test(JSON.stringify(this.body || {}));
  }
}

// Clio wants a comma-separated list, with nested resources in braces:
//   "id,display_number,client{id,name}"
// Accepts a nested object so callers do not hand-build brace syntax.
export function buildFields(spec) {
  if (typeof spec === 'string') return assertFieldsLength(spec);
  if (Array.isArray(spec)) return assertFieldsLength(spec.join(','));
  if (spec && typeof spec === 'object') {
    const parts = [];
    for (const [key, value] of Object.entries(spec)) {
      if (value === true) parts.push(key);
      else if (value === false || value == null) continue;
      else parts.push(`${key}{${buildFieldsInner(value)}}`);
    }
    return assertFieldsLength(parts.join(','));
  }
  throw new TypeError('fields must be a string, array, or object');
}

function buildFieldsInner(spec) {
  if (typeof spec === 'string') return spec;
  if (Array.isArray(spec)) return spec.join(',');
  if (spec && typeof spec === 'object') {
    return Object.entries(spec)
      .map(([k, v]) => (v === true ? k : `${k}{${buildFieldsInner(v)}}`))
      .join(',');
  }
  throw new TypeError('nested fields must be a string, array, or object');
}

export function assertFieldsLength(fields) {
  if (fields.length > FIELDS_MAX_LENGTH) {
    throw new ClioApiError(
      `fields parameter is ${fields.length} characters; Clio rejects anything over ${FIELDS_MAX_LENGTH}. ` +
        'Request fewer fields, or split into more than one call.',
      { status: 0 }
    );
  }
  return fields;
}

export function parseRateLimit(headers) {
  const get = (name) => {
    const raw = typeof headers.get === 'function' ? headers.get(name) : headers[name];
    if (raw == null) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  };
  return {
    limit: get('x-ratelimit-limit'),
    remaining: get('x-ratelimit-remaining'),
    reset: get('x-ratelimit-reset'),
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class ClioClient {
  constructor(config, opts = {}) {
    this.config = config;
    this.fetchImpl = opts.fetchImpl || fetch;
    this.maxRetries = opts.maxRetries ?? 4;
    this.sleepImpl = opts.sleepImpl || sleep;
    this.tokenProvider = opts.tokenProvider || ((cfg) => getAccessToken(cfg, opts));
    // Pace ourselves rather than relying on 429s to tell us; a 429 is a bug we
    // caused, not a signal to wait for.
    //
    // MEASURED 2026-08-20, and it contradicts the docs. Clio documents 50
    // requests/minute. A live trial account reports X-RateLimit-Limit: 600,
    // Remaining decrementing exactly 1 per call, and Reset holding constant at
    // a unix instant while the clock runs down. Observed Reset values were all
    // exact multiples of 60, so the window is one minute aligned to the minute
    // boundary: 600/min, not 600/hour and not the documented 50/min.
    //
    // 150ms is 400/min, two thirds of the observed ceiling. Deliberately not
    // 100ms: the documented figure is far lower than the observed one, so the
    // headroom covers the case where 600 is a trial-account allowance and a
    // production firm's account enforces something tighter.
    this.minIntervalMs = opts.minIntervalMs ?? 150;
    this._lastRequestAt = 0;
    this.lastRateLimit = null;
    this.onRateLimit = opts.onRateLimit || null;
  }

  async _throttle() {
    const now = Date.now();
    const wait = this._lastRequestAt + this.minIntervalMs - now;
    if (wait > 0) await this.sleepImpl(wait);
    this._lastRequestAt = Date.now();
  }

  async request(path, { method = 'GET', query = {}, body, fields, retryOn401 = true } = {}) {
    const url = new URL(
      path.startsWith('http') ? path : `${this.config.region.apiBase}${path}`
    );
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
    if (fields) url.searchParams.set('fields', buildFields(fields));

    let attempt = 0;
    for (;;) {
      attempt += 1;
      await this._throttle();
      const token = await this.tokenProvider(this.config);
      const res = await this.fetchImpl(url.toString(), {
        method,
        headers: {
          authorization: `Bearer ${token.accessToken}`,
          accept: 'application/json',
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });

      this.lastRateLimit = parseRateLimit(res.headers);
      if (this.onRateLimit) this.onRateLimit(this.lastRateLimit);

      if (res.status === 429) {
        const retryAfter = Number(res.headers.get('retry-after'));
        const waitMs = (Number.isFinite(retryAfter) ? retryAfter : 2 ** attempt) * 1000;
        if (attempt > this.maxRetries) {
          throw new ClioApiError(`Rate limited and out of retries after ${attempt} attempts`, {
            status: 429,
            url: url.toString(),
            retryAfter,
          });
        }
        // Obey Retry-After exactly. Guessing shorter is how an integration gets
        // its access reviewed.
        await this.sleepImpl(waitMs);
        continue;
      }

      // A 401 on a token we believed was valid means the stored access token was
      // revoked or expired early. Force one refresh, then give up rather than loop.
      if (res.status === 401 && retryOn401 && attempt <= 2) {
        this.tokenProvider = (cfg) =>
          getAccessToken(cfg, { forceRefresh: true, token: { ...token, expiresAt: 0 } });
        continue;
      }

      if (res.status >= 500 && attempt <= this.maxRetries) {
        await this.sleepImpl(2 ** attempt * 250);
        continue;
      }

      const text = await res.text();
      let parsed;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = { raw: text };
      }

      if (!res.ok) {
        throw new ClioApiError(`Clio API ${method} ${url.pathname} returned ${res.status}`, {
          status: res.status,
          body: parsed,
          url: url.toString(),
        });
      }
      return parsed;
    }
  }

  // Cursor pagination. Deliberately the default and the only paging helper:
  // offset paging silently caps at 10,000 records, and a sync that quietly
  // stops at record 10,000 is worse than one that fails.
  async *paginate(path, { query = {}, fields, pageSize = 100, maxRecords = Infinity } = {}) {
    let nextUrl = null;
    let yielded = 0;
    for (;;) {
      const page = nextUrl
        ? await this.request(nextUrl)
        : await this.request(path, {
            fields,
            query: { ...query, order: 'id(asc)', limit: pageSize },
          });
      const rows = Array.isArray(page?.data) ? page.data : [];
      for (const row of rows) {
        yield row;
        yielded += 1;
        if (yielded >= maxRecords) return;
      }
      nextUrl = page?.meta?.paging?.next || null;
      if (!nextUrl || rows.length === 0) return;
    }
  }

  async collect(path, opts = {}) {
    const out = [];
    for await (const row of this.paginate(path, opts)) out.push(row);
    return out;
  }
}

export { ClioAuthError };
