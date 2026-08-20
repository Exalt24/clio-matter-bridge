import { loadConfig } from './lib/config.mjs';
import { ClioClient } from './lib/clio-client.mjs';

// Second probe. Two questions the docs answer wrongly or not at all:
//
// 1. THE RATE LIMIT, WHICH VARIES. Clio documents 50 requests/minute at peak
//    and says limits are increased off-peak. Observed on one account: 600 in
//    the morning, 50 the same afternoon. Both agree with the docs. A single
//    reading cannot tell you the shape of a varying value, which is exactly the
//    mistake this probe exists to prevent, so it takes several readings and
//    watches how Remaining and Reset move.
//
// 2. THE WEBHOOK CONTRACT. /webhooks is reachable, but registering one needs a
//    public HTTPS callback we do not have yet. Rather than guess the required
//    fields, POST a deliberately incomplete body and read the validation error.
//    The platform's own rejection is the most reliable spec available.

const config = loadConfig();
const client = new ClioClient(config, { minIntervalMs: 700 });
const show = (l, v) => console.log(`  ${String(l).padEnd(22)} ${v}`);

console.log('RATE LIMIT, repeated readings');
const readings = [];
for (let i = 0; i < 5; i += 1) {
  await client.request('/users/who_am_i', { fields: 'id' });
  const rl = client.lastRateLimit;
  readings.push({ at: Date.now(), ...rl });
  const resetIn = rl.reset ? rl.reset - Math.floor(Date.now() / 1000) : null;
  show(`read ${i + 1}`, `limit=${rl.limit} remaining=${rl.remaining} reset=${rl.reset} (in ${resetIn}s)`);
}

const first = readings[0];
const last = readings[readings.length - 1];
const usedOverRun = (first.remaining ?? 0) - (last.remaining ?? 0);
show('calls made', readings.length);
show('remaining fell by', usedOverRun);
show('decrements per call', readings.length > 1 ? (usedOverRun / (readings.length - 1)).toFixed(2) : 'n/a');

// If Reset is a unix instant it should sit in the future and stay roughly
// fixed across a short burst. If it is a seconds-until-reset it will be small
// and shrink. Distinguishing the two decides how a backoff should be computed.
const resetDeltas = readings.map((r) => (r.reset ?? 0) - Math.floor(r.at / 1000));
show('reset minus now', resetDeltas.join(', '));
const looksLikeInstant = resetDeltas.every((d) => Math.abs(d) < 4000 && d > -600);
show('reset looks like', looksLikeInstant ? 'a unix INSTANT' : 'ambiguous, see values');
if (last.limit && Math.max(...resetDeltas) > 120) {
  const windowMin = Math.max(...resetDeltas) / 60;
  show('implied window', `~${windowMin.toFixed(0)} min, so ${last.limit} per window`);
  show('sustained pace', `${(last.limit / windowMin).toFixed(1)} req/min, i.e. ${(60000 / (last.limit / windowMin)).toFixed(0)}ms apart`);
} else {
  show('implied window', 'reset already elapsed or too near; window not determinable from this run');
}

console.log('\nWEBHOOK CONTRACT, learned from validation errors');
const attempts = [
  ['empty body', {}],
  ['url only', { data: { url: 'https://example.com/hook' } }],
  ['url + events', { data: { url: 'https://example.com/hook', events: ['matter.created'] } }],
  ['url + events + model', { data: { url: 'https://example.com/hook', events: ['created'], model: 'matter' } }],
];
for (const [label, body] of attempts) {
  try {
    const r = await client.request('/webhooks', { method: 'POST', body, fields: 'id,url,events,status' });
    show(label, `ACCEPTED: ${JSON.stringify(r?.data).slice(0, 200)}`);
    if (r?.data?.id) {
      await client.request(`/webhooks/${r.data.id}`, { method: 'DELETE' });
      show('', `cleaned up webhook ${r.data.id}`);
    }
  } catch (err) {
    show(label, `${err.status}: ${JSON.stringify(err.body).slice(0, 260)}`);
  }
}

console.log('\nprobe2 complete');
