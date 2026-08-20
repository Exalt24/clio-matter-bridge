import { ok, eq, throws, report } from './_assert.mjs';
import {
  MATTER_ALLOWLIST,
  CONTACT_ALLOWLIST,
  findIdentifiers,
  pseudonymize,
  project,
  prepareForModel,
  ConfidentialityError,
} from '../src/lib/confidentiality.mjs';

// ---------- the allowlist is deny-by-default ----------
const matter = {
  id: 42,
  status: 'Open',
  open_date: '2026-08-01',
  description: 'Smith v. Jones, residential purchase',
  client: { id: 7, name: 'Harriet Okonkwo-Fairbanks' },
  billable: true,
};
const p = project(matter, MATTER_ALLOWLIST);
eq(p.kept.id, 42, 'CONTROL allowlisted field kept');
eq(p.kept.status, 'Open', 'CONTROL second allowlisted field kept');
ok(!('description' in p.kept), 'description withheld, because firms write case captions in it');
ok(!('client' in p.kept), 'client object withheld entirely');
ok(p.withheld.includes('description'), 'withheld fields are reported, not silently dropped');
ok(p.withheld.includes('client'), 'client reported as withheld');
// The direction of the failure is the whole design. A field nobody has
// considered must be excluded, not included.
const withNewField = { ...matter, some_field_clio_added_last_week: 'Jones, Robert' };
const p2 = project(withNewField, MATTER_ALLOWLIST);
ok(!('some_field_clio_added_last_week' in p2.kept), 'an unknown new field is excluded by default (fails closed)');
ok(p2.withheld.includes('some_field_clio_added_last_week'), 'and is reported as withheld');
eq(CONTACT_ALLOWLIST.includes('name'), false, 'contact allowlist deliberately excludes name');
eq(CONTACT_ALLOWLIST.includes('id'), true, 'contact allowlist keeps the opaque id');
await throws(() => project(null, MATTER_ALLOWLIST), /must be an object/, 'null record rejected');
await throws(() => project('str', MATTER_ALLOWLIST), /must be an object/, 'string record rejected');

// ---------- identifier detection ----------
const hay =
  'Contact Harriet at h.okonkwo@example.invalid or (410) 555-0134. SSN 123-45-6789. ' +
  'She lives at 42 Maple Street. Case is Smith v. Jones. Card 4111 1111 1111 1111.';
const found = findIdentifiers(hay);
const kinds = new Set(found.map((f) => f.kind));
ok(kinds.has('email'), 'email detected');
ok(kinds.has('phone'), 'phone detected');
ok(kinds.has('ssn'), 'SSN detected');
ok(kinds.has('street_address'), 'street address detected');
ok(kinds.has('case_caption'), 'case caption detected, because it names both parties');
ok(kinds.has('card_number'), 'card number detected');
eq(findIdentifiers('Nothing sensitive here at all.').length, 0, 'CONTROL clean text yields no findings');
// Near-misses that must NOT be flagged, or the tool cries wolf and gets ignored.
eq(findIdentifiers('The matter opened in 2026 and closed in 2027.').length, 0, 'plain years not flagged');
eq(findIdentifiers('Status: Open. Billable: true.').length, 0, 'ordinary field values not flagged');
eq(findIdentifiers('We met at the office.').length, 0, 'prose without identifiers not flagged');

// ---------- pseudonymisation is stable ----------
const ps = pseudonymize('Email a@b.invalid then a@b.invalid again, and c@d.invalid once.');
eq(ps.removed, 2, 'two distinct emails recorded');
const tokens = ps.text.match(/\[EMAIL_\d+\]/g) || [];
eq(tokens.length, 3, 'all three occurrences replaced');
eq(tokens[0], tokens[1], 'the SAME value maps to the SAME token, so the model can still reason about one party');
ok(tokens[0] !== tokens[2], 'different values map to different tokens');
ok(!ps.text.includes('a@b.invalid'), 'original value absent from the outbound text');
ok(!ps.text.includes('c@d.invalid'), 'second original value absent too');
eq(ps.mapping['[EMAIL_1]'], 'a@b.invalid', 'mapping allows LOCAL re-identification');
eq(pseudonymize('no identifiers').removed, 0, 'CONTROL clean text is unchanged');
eq(pseudonymize('no identifiers').text, 'no identifiers', 'clean text passes through verbatim');

// ---------- the chokepoint ----------
const prepared = prepareForModel(matter, { allowlist: MATTER_ALLOWLIST });
ok(!prepared.outbound.includes('Smith'), 'no party name in the outbound payload');
ok(!prepared.outbound.includes('Jones'), 'no opposing party name either');
ok(!prepared.outbound.includes('Okonkwo'), 'no client surname');
ok(prepared.outbound.includes('Open'), 'CONTROL non-identifying content survives, so this is not just deleting everything');
eq(prepared.audit.fields_sent.sort(), ['billable', 'id', 'open_date', 'status'], 'audit names exactly what was sent');
ok(prepared.audit.fields_withheld.includes('description'), 'audit names what was withheld');
eq(prepared.audit.outbound_sha256.length, 64, 'audit records a sha256 of the outbound payload');
ok(!JSON.stringify(prepared.audit).includes('Smith'), 'the AUDIT RECORD is not a second copy of the confidential data');
ok(!JSON.stringify(prepared.audit).includes('Okonkwo'), 'audit contains no client name');
ok(prepared.audit.outbound_bytes > 0, 'audit records the payload size');
ok(typeof prepared.audit.at === 'string', 'audit is timestamped');

// An identifier surviving the allowlist is an allowlist BUG and must be loud.
const badAllowlist = ['id', 'description'];
await throws(
  () => prepareForModel(matter, { allowlist: badAllowlist }),
  /Fix the allowlist/,
  'an identifier surviving the allowlist raises rather than being quietly scrubbed'
);
try {
  prepareForModel(matter, { allowlist: badAllowlist });
} catch (err) {
  ok(err instanceof ConfidentialityError, 'throws the typed error');
  eq(err.reason, 'identifier_survived_allowlist', 'reason is machine-readable');
}
// Non-strict mode scrubs instead of throwing, for a caller that has accepted
// the risk deliberately. It must still not emit the raw value.
const lenient = prepareForModel(matter, { allowlist: badAllowlist, strict: false });
ok(!lenient.outbound.includes('Smith v. Jones'), 'non-strict mode still removes the caption');
ok(lenient.audit.identifiers_replaced > 0, 'non-strict mode records how many identifiers it replaced');

report('confidentiality');
