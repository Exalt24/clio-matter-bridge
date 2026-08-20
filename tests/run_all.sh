#!/bin/sh
# Every suite. Re-run after ANY edit: a file changed since its last clean run is
# unverified regardless of whether it passed before the edit.
#
# The offline suites need nothing. The live suite needs `npm run auth` plus
# seeded records, so it SKIPS loudly rather than failing a fresh clone.
fail=0

run() {
  label="$1"
  shift
  printf "%-40s " "$label"
  if "$@" >/dev/null 2>&1; then
    echo PASS
  else
    echo FAIL
    fail=1
  fi
}

run "oauth (64 checks)"            node tests/oauth.test.mjs
run "client (32 checks)"           node tests/client.test.mjs
run "webhook (72 checks)"          node tests/webhook.test.mjs
run "confidentiality (47 checks)"  node tests/confidentiality.test.mjs
run "captured real Clio bytes (25)"  node tests/captured.test.mjs

printf "%-40s " "live against real Clio (25 checks)"
if [ -f .tokens.json ]; then
  if node tests/live.test.mjs >/dev/null 2>&1; then
    echo PASS
  else
    echo FAIL
    fail=1
  fi
else
  echo "SKIP (no .tokens.json; run: npm run auth)"
fi

# Mutation controls. A suite that cannot go red is not a suite. Each of these
# breaks one guard, asserts the relevant suite FAILS, and restores the file.
mutate() {
  label="$1"; file="$2"; suite="$3"; find_str="$4"; repl="$5"
  printf "%-40s " "mutation: $label"
  cp "$file" "$file.mutbak"
  python -c "
import sys
p = sys.argv[1]
s = open(p, encoding='utf8').read()
old, new = sys.argv[2], sys.argv[3]
if old not in s:
    sys.exit('mutation target missing')
open(p, 'w', encoding='utf8').write(s.replace(old, new))
" "$file" "$find_str" "$repl" 2>/dev/null || { echo "SKIP (target moved)"; rm -f "$file.mutbak"; return; }
  if node "$suite" >/dev/null 2>&1; then
    echo "FAIL (suite stayed green with the guard broken)"
    fail=1
  else
    echo PASS
  fi
  mv "$file.mutbak" "$file"
}

mutate "localhost redirect guard" \
  src/lib/config.mjs tests/oauth.test.mjs \
  "if (parsed.protocol === 'http:' && parsed.hostname === 'localhost') {" \
  "if (false) {"

mutate "webhook signature compare" \
  src/lib/webhook.mjs tests/webhook.test.mjs \
  "  return timingSafeEqual(Buffer.from(candidate), Buffer.from(expected));" \
  "  return true;"

mutate "confidentiality allowlist" \
  src/lib/confidentiality.mjs tests/confidentiality.test.mjs \
  "    if (allowlist.includes(key)) kept[key] = value;" \
  "    if (true) kept[key] = value;"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL SUITES PASS"
else
  echo "FAILURES ABOVE"
fi
exit "$fail"
