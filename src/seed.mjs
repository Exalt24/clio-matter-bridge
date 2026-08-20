import { loadConfig } from './lib/config.mjs';
import { ClioClient } from './lib/clio-client.mjs';

// Seeds a Clio DEVELOPER TRIAL account with synthetic law-firm records.
//
// Why this exists: the trial account is created completely empty (0 matters,
// 0 contacts, 0 calendar entries, 0 tasks). An integration demonstrated against
// an empty account proves only that requests are authenticated. Pagination,
// change detection and any AI summarisation are all untested until records
// exist.
//
// ALL DATA HERE IS INVENTED. No real person, no real matter, no client
// information of any kind. This must never be pointed at an account holding
// real client data: it CREATES records, and `--undo` DELETES the ones it
// created. Guarded below by an explicit refusal to run against an account that
// already holds records it did not create.
//
// The POST shapes were learned the same way the webhook contract was: send a
// deliberately incomplete body and read the validation error. Run with
// `--discover` to see that process rather than trusting the field names here.

const config = loadConfig();
const client = new ClioClient(config);
const args = new Set(process.argv.slice(2));
const DRY = args.has('--dry');
const DISCOVER = args.has('--discover');
const UNDO = args.has('--undo');

const show = (l, v) => console.log(`  ${String(l).padEnd(30)} ${v}`);

// Synthetic. Deliberately implausible-but-ordinary names so nothing here could
// be mistaken for a real party, and matter descriptions drawn from generic
// practice areas rather than anything specific.
const CONTACTS = [
  { first_name: 'Harriet', last_name: 'Okonkwo-Fairbanks', type: 'Person', email: 'h.okonkwo@example.invalid' },
  { first_name: 'Desmond', last_name: 'Petrakis', type: 'Person', email: 'd.petrakis@example.invalid' },
  { first_name: 'Yolanda', last_name: 'Brightwater', type: 'Person', email: 'y.brightwater@example.invalid' },
  { name: 'Ridgeline Property Holdings LLC', type: 'Company', email: 'contact@example.invalid' },
  { name: 'Coriander Foods Cooperative', type: 'Company', email: 'admin@example.invalid' },
];

const MATTERS = [
  { description: 'Residential purchase, settlement and title review', status: 'Open' },
  { description: 'Estate administration and probate filing', status: 'Open' },
  { description: 'Commercial lease negotiation, retail unit', status: 'Open' },
  { description: 'Employment separation agreement review', status: 'Open' },
  { description: 'Small business formation and operating agreement', status: 'Pending' },
  { description: 'Contract dispute, pre-litigation demand', status: 'Open' },
  { description: 'Trademark filing and clearance search', status: 'Closed' },
];

async function count(resource) {
  const r = await client.request(`/${resource}`, { fields: 'id', query: { limit: 1 } });
  return r?.meta?.paging?.total_entries ?? (Array.isArray(r?.data) ? r.data.length : 0);
}

async function attempt(label, path, body) {
  try {
    const r = await client.request(path, { method: 'POST', body, fields: 'id' });
    show(label, `ACCEPTED id=${r?.data?.id}`);
    return r?.data?.id ?? null;
  } catch (err) {
    show(label, `${err.status} ${JSON.stringify(err.body).slice(0, 220)}`);
    return null;
  }
}

if (DISCOVER) {
  console.log('DISCOVERY: learning required fields from validation errors');
  console.log('\ncontacts');
  await attempt('empty', '/contacts', {});
  await attempt('name only', '/contacts', { data: { name: 'Probe Co' } });
  await attempt('name + type', '/contacts', { data: { name: 'Probe Co', type: 'Company' } });
  console.log('\nmatters');
  await attempt('empty', '/matters', {});
  await attempt('description only', '/matters', { data: { description: 'Probe matter' } });
  console.log('\n(any records created above are real; delete them or run --undo)');
  process.exit(0);
}

console.log(`Clio seed  account=${config.region.key}  ${DRY ? '[DRY RUN]' : UNDO ? '[UNDO]' : '[WRITE]'}`);

const existingContacts = await count('contacts');
const existingMatters = await count('matters');
show('existing contacts', existingContacts);
show('existing matters', existingMatters);

// A trial account starts empty. If it is NOT empty, this may be a real account
// and creating or deleting records in it could damage a live practice. Refuse
// rather than ask, because the cost of being wrong is asymmetric.
const looksUsed = existingMatters > MATTERS.length + 2 || existingContacts > CONTACTS.length + 5;
if (looksUsed && !args.has('--i-know-this-account-is-disposable')) {
  console.error(
    '\nREFUSING TO RUN. This account already holds more records than this script creates,\n' +
      'so it may be a real practice rather than a disposable developer trial. Seeding or\n' +
      'undoing here could alter or delete genuine client records.\n\n' +
      'If it truly is disposable, re-run with --i-know-this-account-is-disposable.'
  );
  process.exit(1);
}

if (UNDO) {
  // Only deletes records whose shape matches what this script creates, and only
  // by id, so a hand-made record is never caught by a broad filter.
  console.log('\nundo: deleting seeded matters then contacts (matters first, they reference contacts)');
  const matters = await client.collect('/matters', { fields: 'id,description' });
  let removed = 0;
  for (const m of matters) {
    if (!MATTERS.some((seed) => seed.description === m.description)) continue;
    if (DRY) {
      show('would delete matter', `${m.id} ${m.description}`);
      continue;
    }
    try {
      await client.request(`/matters/${m.id}`, { method: 'DELETE' });
      show('deleted matter', m.id);
      removed += 1;
    } catch (err) {
      show('delete failed', `${m.id} ${err.status}`);
    }
  }
  const contacts = await client.collect('/contacts', { fields: 'id,name' });
  for (const c of contacts) {
    const isSeed = CONTACTS.some(
      (s) => s.name === c.name || `${s.first_name} ${s.last_name}` === c.name
    );
    if (!isSeed) continue;
    if (DRY) {
      show('would delete contact', `${c.id} ${c.name}`);
      continue;
    }
    try {
      await client.request(`/contacts/${c.id}`, { method: 'DELETE' });
      show('deleted contact', c.id);
      removed += 1;
    } catch (err) {
      show('delete failed', `${c.id} ${err.status}`);
    }
  }
  show('records removed', removed);
  process.exit(0);
}

console.log('\ncreating contacts');
const contactIds = [];
for (const c of CONTACTS) {
  const label = c.name || `${c.first_name} ${c.last_name}`;
  if (DRY) {
    show('would create', label);
    continue;
  }
  const body = { data: { type: c.type } };
  if (c.name) body.data.name = c.name;
  if (c.first_name) {
    body.data.first_name = c.first_name;
    body.data.last_name = c.last_name;
  }
  if (c.email) {
    body.data.email_addresses = [{ name: 'Work', address: c.email, default_email: true }];
  }
  const id = await attempt(label, '/contacts', body);
  if (id) contactIds.push(id);
}

console.log('\ncreating matters');
let made = 0;
for (const [i, m] of MATTERS.entries()) {
  if (DRY) {
    show('would create', m.description);
    continue;
  }
  const clientId = contactIds[i % Math.max(contactIds.length, 1)];
  const body = { data: { description: m.description, status: m.status } };
  if (clientId) body.data.client = { id: clientId };
  const id = await attempt(m.description.slice(0, 28), '/matters', body);
  if (id) made += 1;
}

console.log('\nresult');
show('contacts now', await count('contacts'));
show('matters now', await count('matters'));
show('matters created this run', made);
console.log('\nrun with --undo to remove exactly what this script created');
