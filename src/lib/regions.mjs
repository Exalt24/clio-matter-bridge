// Clio runs four independent regional instances. A token issued in one region is
// not valid against another region's API, so every URL in the app derives from
// one region key rather than being written out by hand.
//
// Deliberately Clio MANAGE endpoints. Clio Platform (the Grow-side API) authorizes
// at auth.api.clio.com, which is a different product; mixing the two produces
// 404s that look like a broken request rather than a wrong host.
// Source: docs.developers.clio.com/handbook/getting-started/regions/

const REGIONS = {
  us: { host: 'app.clio.com' },
  eu: { host: 'eu.app.clio.com' },
  ca: { host: 'ca.app.clio.com' },
  au: { host: 'au.app.clio.com' },
};

export function regionKeys() {
  return Object.keys(REGIONS);
}

export function resolveRegion(region) {
  const key = String(region || '').trim().toLowerCase();
  const entry = REGIONS[key];
  if (!entry) {
    throw new Error(
      `Unknown Clio region "${region}". Expected one of: ${regionKeys().join(', ')}`
    );
  }
  const base = `https://${entry.host}`;
  return {
    key,
    host: entry.host,
    apiBase: `${base}/api/v4`,
    authorizeUrl: `${base}/oauth/authorize`,
    tokenUrl: `${base}/oauth/token`,
  };
}
