import { createHash } from 'node:crypto';

// THE CONFIDENTIALITY BOUNDARY.
//
// This is the part that makes the integration a legal tool rather than a
// generic CRM sync. A law firm's duty of confidentiality under ABA Model Rule
// 1.6 covers ALL information relating to a representation, not merely
// privileged material, and ABA Formal Opinion 512 (29 July 2024) applies that
// squarely to generative AI: a lawyer must consider whether information put
// into a GAI tool could surface in a later output, and in some circumstances
// must obtain informed client consent before putting it in at all.
//
// The engineering consequence is the design rule below, and it is the opposite
// of how most integrations are built:
//
//   DENY BY DEFAULT. A field leaves this machine only if it is on an explicit
//   allowlist. Adding a field to a prompt is a deliberate, reviewable act.
//
// A denylist is the wrong shape here and the reason is not stylistic. A
// denylist fails open: the day Clio adds a field, or a firm puts a client name
// in a matter description, the new value is transmitted because nobody thought
// to forbid it. An allowlist fails closed, which is the only acceptable
// direction when the failure mode is disclosing client information.
//
// The cheapest way to protect a client's name is not to send it.

export class ConfidentialityError extends Error {
  constructor(message, { field, reason } = {}) {
    super(message);
    this.name = 'ConfidentialityError';
    this.field = field;
    this.reason = reason;
  }
}

// Fields on a Clio matter that carry no party-identifying information and are
// therefore safe to describe to a third-party model. Deliberately short.
// `description` is NOT here: firms routinely write "Smith v. Jones" into it.
export const MATTER_ALLOWLIST = Object.freeze([
  'id',
  'status',
  'open_date',
  'close_date',
  'practice_area',
  'billable',
  'matter_stage',
]);

export const CONTACT_ALLOWLIST = Object.freeze(['id', 'type']);

// Patterns for values that must never leave, checked on whatever survives the
// allowlist. This is defence in depth, not the primary control: the allowlist
// is. A regex sweep alone would be the denylist mistake.
const IDENTIFIER_PATTERNS = [
  [/\b\d{3}-\d{2}-\d{4}\b/g, 'ssn'],
  [/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, 'email'],
  [/\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b/g, 'phone'],
  [/\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Boulevard|Blvd)\b/g, 'street_address'],
  [/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, 'card_number'],
  // "Smith v. Jones" / "Smith vs Jones": a case caption names both parties.
  [/\b[A-Z][a-z]+\s+v(?:s?\.?)\s+[A-Z][a-z]+\b/g, 'case_caption'],
];

export function findIdentifiers(text) {
  const found = [];
  for (const [pattern, kind] of IDENTIFIER_PATTERNS) {
    for (const match of String(text).matchAll(pattern)) {
      found.push({ kind, value: match[0], index: match.index });
    }
  }
  return found;
}

// Replaces identifiers with STABLE placeholders. Stability matters: the same
// person must map to the same token across a document so the model can still
// reason about "the same party" without ever learning who they are.
export function pseudonymize(text, { salt = 'clio-matter-bridge' } = {}) {
  const mapping = new Map();
  let out = String(text);
  const counters = {};
  for (const [pattern, kind] of IDENTIFIER_PATTERNS) {
    out = out.replace(pattern, (match) => {
      if (mapping.has(match)) return mapping.get(match);
      counters[kind] = (counters[kind] || 0) + 1;
      const token = `[${kind.toUpperCase()}_${counters[kind]}]`;
      mapping.set(match, token);
      return token;
    });
  }
  return {
    text: out,
    // The map is returned for LOCAL re-identification only. It must never be
    // sent anywhere; that would defeat the entire exercise.
    mapping: Object.fromEntries([...mapping].map(([k, v]) => [v, k])),
    removed: mapping.size,
  };
}

// Projects a record down to its allowlist. Anything not named is dropped, and
// the dropped keys are reported so the caller can see what was withheld rather
// than discovering later that a field silently vanished.
export function project(record, allowlist) {
  if (!record || typeof record !== 'object') {
    throw new ConfidentialityError('record must be an object', { reason: 'bad_input' });
  }
  const kept = {};
  const withheld = [];
  for (const [key, value] of Object.entries(record)) {
    if (allowlist.includes(key)) kept[key] = value;
    else withheld.push(key);
  }
  return { kept, withheld };
}

// The single chokepoint. Nothing in this project sends text to a model except
// through here, so there is exactly one place to audit.
export function prepareForModel(payload, { allowlist, salt, strict = true } = {}) {
  const { kept, withheld } = project(payload, allowlist);
  const serialized = JSON.stringify(kept);
  const leaks = findIdentifiers(serialized);

  if (leaks.length && strict) {
    // An identifier surviving the allowlist means the allowlist is wrong, not
    // that the text needs scrubbing. Failing loudly forces the allowlist to be
    // fixed instead of quietly patching the symptom on every call.
    throw new ConfidentialityError(
      `allowlisted fields still contain ${leaks.length} identifier(s): ` +
        `${[...new Set(leaks.map((l) => l.kind))].join(', ')}. Fix the allowlist.`,
      { field: Object.keys(kept).join(','), reason: 'identifier_survived_allowlist' }
    );
  }

  const scrubbed = leaks.length ? pseudonymize(serialized, { salt }) : { text: serialized, mapping: {}, removed: 0 };

  return {
    outbound: scrubbed.text,
    mapping: scrubbed.mapping,
    // The audit record is the deliverable a firm can actually be shown. It
    // records a HASH of what left, never the content, so the audit log itself
    // is not a second copy of the confidential data.
    audit: {
      at: new Date().toISOString(),
      fields_sent: Object.keys(kept),
      fields_withheld: withheld,
      identifiers_replaced: scrubbed.removed,
      outbound_sha256: createHash('sha256').update(scrubbed.text).digest('hex'),
      outbound_bytes: Buffer.byteLength(scrubbed.text, 'utf8'),
    },
  };
}
