// Tiny harness. No dependencies so the suite runs on a bare clone.
let passed = 0;
const failures = [];

export function ok(cond, label) {
  if (cond) {
    passed += 1;
  } else {
    failures.push(label);
  }
}

export function eq(actual, expected, label) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  ok(a === e, `${label} (expected ${e}, got ${a})`);
}

// Every negative test in this suite is preceded by a POSITIVE CONTROL asserting
// the same code path succeeds on good input. Without the control, a function
// broken so badly that it throws on everything would pass every "it rejects"
// test, and the suite would report green while enforcing nothing.
export async function throws(fn, match, label) {
  try {
    await fn();
    ok(false, `${label} (expected a throw, got none)`);
  } catch (err) {
    const m = match instanceof RegExp ? match.test(err.message) : String(err.message).includes(match);
    ok(m, `${label} (message did not match ${match}: "${err.message}")`);
  }
}

export function report(name) {
  const total = passed + failures.length;
  if (failures.length) {
    console.error(`${name}: ${passed}/${total} passed, ${failures.length} FAILED`);
    for (const f of failures) console.error(`  FAIL ${f}`);
    process.exit(1);
  }
  console.log(`${name}: ${passed}/${total} checks passed`);
}
