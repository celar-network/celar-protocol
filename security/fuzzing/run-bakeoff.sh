#!/usr/bin/env bash
# Run the bake-off harness and keep the output with an environment manifest.
#
# Every published figure must be traceable to the machine and commit that
# produced it, so the manifest is written alongside the log and a run without
# one is not citable. Hardware is recorded deliberately: timings are
# meaningless without it. Filesystem paths are not recorded, and harness
# output is scrubbed of them, since they carry no provenance value.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ART="$HERE/artifacts"
VENV="$REPO/fhe/backend-adapter/.venv"
mkdir -p "$ART"

STAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
{
  echo "# Celar bake-off environment manifest"
  echo "utc:            $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host-cpu:       $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
  echo "cores:          $(nproc)  (TFHE-rs parallelises internally)"
  echo "mem-total-gb:   $(free -g | awk '/^Mem:/{print $2}')"
  echo "kernel:         $(uname -sr)"
  echo "rustc:          $(rustc --version 2>/dev/null || echo n/a)"
  echo "tfhe-version:   $(grep -A1 '^name = "tfhe"$' \
                          "$REPO/fhe/backend-adapter/zama/Cargo.lock" \
                          | grep '^version' | head -1 | cut -d'"' -f2)"
  echo "build-profile:  release; gpu off; avx512 on"
  echo "operands:       real client encryption (trivial reserved for public constants)"
  echo "git-commit:     $(git -C "$REPO" rev-parse HEAD)"
  echo "git-dirty:      $(git -C "$REPO" diff --quiet && echo no || echo YES)"
} > "$ART/env-$STAMP.txt"
cat "$ART/env-$STAMP.txt"

[ -d "$VENV" ] && source "$VENV/bin/activate"
echo
echo "=== running harness ==="
python "$HERE/bakeoff_harness.py" 2>&1 \
  | sed "s#$HOME#<home>#g; s#$REPO#<repo>#g" \
  | tee "$ART/bakeoff-$STAMP.txt"
echo
echo "artifacts: env-$STAMP.txt, bakeoff-$STAMP.txt"
