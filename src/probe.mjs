import { loadConfig } from './lib/config.mjs';
import { ClioClient, ClioApiError, buildFields } from './lib/clio-client.mjs';

// Live reconnaissance against a real Clio account. Exists because the docs do
// not tell you what a given account actually contains, nor how the platform
// behaves at the edges. Every finding here is observed, not assumed.

const config = loadConfig();
const client = new ClioClient(config, { minIntervalMs: 1300 });

const line = (s = '') => console.log(s);
const show = (label, value) => console.log(`  ${label.padEnd(26)} ${value}`);

async function probe(label, fn) {
  try {
    const value = await fn();
    line(`\n[OK] ${label}`);
    return value;
  } catch (err) {
    line(`\n[!!] ${label}`);
    if (err instanceof ClioApiError) {
      show('status', err.status);
      show('body', JSON.stringify(err.body).slice(0, 400));
    } else {
      show('error', err.message);
    }
    return null;
  }
}

line('Clio live probe');
line(`region ${config.region.key}  base ${config.region.apiBase}`);

// 1. Who am I. Confirms the token works and names the account.
const me = await probe('GET /users/who_am_i', async () => {
  const r = await client.request('/users/who_am_i', {
    fields: 'id,name,first_name,last_name,email,enabled,subscription_type,account{id,name}',
  });
  const u = r?.data || {};
  show('user id', u.id);
  show('name', u.name || `${u.first_name || ''} ${u.last_name || ''}`.trim());
  show('email', u.email);
  show('subscription_type', u.subscription_type ?? '(not returned)');
  show('account', u.account ? `${u.account.id} ${u.account.name}` : '(not returned)');
  return r;
});

line('\nrate limit headers on that call:');
show('limit', client.lastRateLimit?.limit ?? '(absent)');
show('remaining', client.lastRateLimit?.remaining ?? '(absent)');
show('reset', client.lastRateLimit?.reset ?? '(absent)');

// 2. What does this account hold? A trial is usually empty, which matters:
// an integration demoed against an empty account proves nothing.
const RESOURCES = [
  ['matters', 'id,display_number,description,status,open_date,client{id,name}'],
  ['contacts', 'id,name,first_name,last_name,type,primary_email_address'],
  ['calendar_entries', 'id,summary,start_at,end_at,all_day'],
  ['tasks', 'id,name,status,due_at,priority'],
  ['documents', 'id,name,created_at,size'],
  ['activities', 'id,type,date,quantity,total'],
  ['practice_areas', 'id,name'],
  ['custom_fields', 'id,name,field_type,parent_type,displayed,required'],
  ['users', 'id,name,email,enabled'],
];

line('\nresource inventory');
const counts = {};
for (const [resource, fields] of RESOURCES) {
  try {
    const r = await client.request(`/${resource}`, { fields, query: { limit: 1 } });
    const total = r?.meta?.paging?.total_entries ?? r?.meta?.records ?? '(no total in meta)';
    counts[resource] = total;
    const sample = Array.isArray(r?.data) && r.data[0] ? Object.keys(r.data[0]).join(',') : '(empty)';
    show(resource, `total=${total}  keys=${sample}`);
  } catch (err) {
    counts[resource] = `ERROR ${err.status}`;
    show(resource, `ERROR ${err.status} ${JSON.stringify(err.body).slice(0, 160)}`);
  }
}

// 3. Confirm the documented fields ceiling is real and enforced client-side
// before a wasted round trip.
line('\nfields parameter ceiling');
try {
  buildFields('a'.repeat(1001));
  show('1001 chars', 'NOT rejected locally, which contradicts the documented limit');
} catch (err) {
  show('1001 chars', `rejected locally: ${err.message.slice(0, 90)}`);
}

// 4. Does the platform actually expose webhooks on this plan? The answer
// decides whether the integration is event-driven or polling-based, so it is
// worth an explicit probe rather than an assumption either way.
line('\nwebhook support');
for (const path of ['/webhooks']) {
  try {
    const r = await client.request(path, { fields: 'id,url,events,status,expires_at' });
    show(path, `reachable, ${Array.isArray(r?.data) ? r.data.length : 0} registered`);
    if (r?.data?.length) show('existing', JSON.stringify(r.data).slice(0, 300));
  } catch (err) {
    show(path, `status ${err.status} ${JSON.stringify(err.body).slice(0, 200)}`);
  }
}

// 5. Change detection. Without a usable updated_since filter, an incremental
// sync has to re-read everything, which the rate limit makes painful.
line('\nchange detection on matters');
for (const param of ['updated_since', 'created_since']) {
  try {
    const r = await client.request('/matters', {
      fields: 'id,updated_at',
      query: { [param]: '2020-01-01T00:00:00Z', limit: 1 },
    });
    show(param, `accepted, returned ${Array.isArray(r?.data) ? r.data.length : 0}`);
  } catch (err) {
    show(param, `rejected, status ${err.status}`);
  }
}

line('\nprobe complete');
