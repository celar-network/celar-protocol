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
# H is deliberately absent: H60/H100 is our own ciphertext-handle
# notation in comments. E/W/R/T are two digits because ours are —
# three digits swallowed a `# noqa: E402` lint code.
# G starts at 7: G1-G6 are published design-goal names the whitepaper
# uses (G2 = no data-dependent branching, G5 = supply invariant, ...),
# so source is RIGHT to use them; only G7 and up are internal
# deliverable rows. A blanket G would report published vocabulary as a
# leak, and a check that fails on correct files is a check people
# learn to skip.
# Not preceded by a hyphen: shell is full of -A1, -B2, -C3 as grep flags,
# and a word boundary alone treats the hyphen as one. Third pattern
# correction of this kind, and like the others it narrows the pattern
# rather than excluding a file - a check that reports correct files as
# leaks is a check people learn to skip.
# SR added 2026-09-25: the security lane's prefix matched NOTHING here. It is
# not in the single-letter class, and SEC[0-9] does not cover it, so four
# `SR9` references sat in source and the check reported the tree clean. Found
# by eye while rewording a different id in the same comment — which is exactly
# the discovery route this script exists to replace.
#
# Fifth narrowing-or-widening of this pattern, and the fourth time the cause
# was the same: the alphabet was narrower than the target. The header already
# says a sweep "missed five sites its own grep alphabet could not match"; the
# guard written from that lesson then reproduced it.
IDS='(^|[^-[:alnum:]])([ABCDEIQ][0-9]{1,2}|G([7-9]|[1-9][0-9])|D[0-9](\.[0-9]+)?|[EWRT][0-9]{1,2}|SR[0-9]{1,2}|SEC[0-9]|LIC[0-9])\b'
LANES='(Track [ABCD]\b|ENGG-[12]|engineer #[12]|work order|celar-progress-tracker)'

# Text mode: the same two patterns, applied to a message instead of a tree.
#
# Messages are the surface that cannot be corrected afterwards. Linear history
# and no force-push mean a message on the trunk is permanent, and squash-merge
# makes the PR TITLE the message that lands - so a hook over local commits
# guards the drafts and misses the artifact. Both surfaces call this.
#
# Patterns are shared with the file scan below deliberately: two regexes for
# one rule is two records of one fact, and this project has paid for that.
if [ "${1:-}" = "--text" ]; then
  message=$(cat)
  hit=0
  printf '%s\n' "$message" | grep -nE "$IDS" && hit=1
  printf '%s\n' "$message" | grep -nE "$LANES" && hit=1
  if [ "$hit" -ne 0 ]; then
    echo
    echo "FAIL: internal vocabulary in a message that will be permanent."
    echo "Describe the thing, don't name our tracker row for it."
    exit 1
  fi
  echo "OK: message carries no internal ids or lane vocabulary."
  exit 0
fi

exclude=(--exclude-dir=.git --exclude-dir=out --exclude-dir=lib
         --exclude-dir=cache --exclude-dir=node_modules --exclude-dir=target
         --exclude-dir=scripts)

# .sh was missing until 2026-09-04 and a devnet script had carried an
# internal identifier in a comment since it was written. Shell is where
# setup reasoning lives, and setup reasoning is exactly where someone
# explains WHY - which is where our own vocabulary turns up.
types=(--include='*.go' --include='*.sol' --include='*.rs'
       --include='*.py' --include='*.md' --include='*.yml' --include='*.toml'
       --include='*.sh' --include='*.json' --include='Makefile')

echo "== internal work-item ids =="
if grep -rnE "$IDS" "${types[@]}" "${exclude[@]}" . ; then fail=1; fi

echo "== lane vocabulary =="
if grep -rnE "$LANES" "${types[@]}" "${exclude[@]}" . ; then fail=1; fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "FAIL: internal vocabulary found in a public-bound file."
  echo "Describe the thing, don't name our tracker row for it."
  exit 1
fi
echo "OK: no internal ids or lane vocabulary."
