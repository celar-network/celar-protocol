#!/usr/bin/env bash
# Refuses internal work-item ids and lane vocabulary in source files.
#
# This exists because stripping them by hand did not hold: a sweep on
# 2026-08-27 missed five sites its own grep alphabet could not match,
# and an id reached a committed test comment three days later, written
# by the person who ran the sweep. A rule that lives in someone's
# memory is not a guard.
#
# Case-sensitive and word-bounded on purpose: "A6" is an id, "0xA6" and
# "a6a6a6a6" are data, and a case-insensitive pattern floods on hex.

set -u
fail=0

# Uppercase-letter + digits, word-bounded. M is deliberately absent —
# M1/M2 are milestone names that plausibly appear in public roadmap
# material, and stripping them would cost real meaning. If the owner
# rules milestones internal, add M here.
# H is deliberately absent: it is Track B's prefix, that tree is
# excluded anyway, and H60/H100 is our own ciphertext-handle
# notation in comments. E/W/R/T are two digits because ours are —
# three digits swallowed a `# noqa: E402` lint code.
IDS='\b([ABCDEGIQ][0-9]{1,2}|D[0-9](\.[0-9]+)?|[EWRT][0-9]{1,2}|SEC[0-9]|LIC[0-9])\b'
LANES='(Track [ABCD]\b|ENGG-[12]|engineer #[12]|work order|celar-progress-tracker)'

exclude=(--exclude-dir=.git --exclude-dir=out --exclude-dir=lib
         --exclude-dir=cache --exclude-dir=node_modules --exclude-dir=target
         --exclude-dir=scripts --exclude-dir=kms)

types=(--include='*.go' --include='*.sol' --include='*.rs'
       --include='*.py' --include='*.md' --include='*.yml' --include='*.toml')

echo "== internal work-item ids =="
if grep -rnE "$IDS" "${types[@]}" "${exclude[@]}" . ; then fail=1; fi

echo "== lane vocabulary =="
if grep -rnE "$LANES" "${types[@]}" "${exclude[@]}" . ; then fail=1; fi

# Stated loudly rather than left as a silent exclusion, which is how an
# interim measure becomes permanent.
echo
echo "NOTE: kms/ is excluded pending its own rename pass (concept names,"
echo "not bare stripping — the ids are load-bearing in that prose)."
echo "Remove --exclude-dir=kms from this script when that lands."

if [ "$fail" -ne 0 ]; then
  echo
  echo "FAIL: internal vocabulary found in a public-bound file."
  echo "Describe the thing, don't name our tracker row for it."
  exit 1
fi
echo "OK: no internal ids or lane vocabulary outside kms/."
