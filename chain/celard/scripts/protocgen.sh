#!/usr/bin/env bash
# Regenerate the chain's protobuf Go from proto/.
#
# Why this file exists: the committed *.pb.go were produced by a toolchain that
# lived on one machine and nowhere in this repository. They encode consensus
# messages, so "generated once by someone" is not a safe state — a later
# regeneration with different plugin versions can differ from what is committed,
# in files nobody reads.
#
# Run from anywhere:
#   chain/celard/scripts/protocgen.sh
#
# Idempotent by design: running it on a clean tree must leave the tree clean.
# That property is the actual check — if this script's output differs from what
# is committed, either the .proto or the .pb.go has drifted from the other, and
# that is exactly the failure the absence of this file made invisible.
#
# Deliberately NOT buf: buf resolves its dependencies from a remote registry,
# which makes generation depend on a network service and on versions chosen
# there rather than the ones this module compiles against. Resolving the
# includes from the Go module cache instead means the protos we build with are
# the protos our dependencies ship — the same versions, by construction.
set -euo pipefail

CELARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$CELARD_DIR"

command -v protoc >/dev/null || {
  echo "protoc not found. On Debian/Ubuntu: sudo apt install -y protobuf-compiler" >&2
  exit 1
}

MODCACHE="$(go env GOMODCACHE)"

# Each include is pinned to the version in go.mod rather than to whatever is
# newest. Generation moving ahead of the library that decodes the result is the
# drift this script exists to prevent, so it must not introduce it itself.
dep_dir() {
  local module="$1"
  local version
  version="$(go list -m -f '{{.Version}}' "$module")"
  echo "${MODCACHE}/$(echo "$module" | sed 's/\([A-Z]\)/!\L\1/g')@${version}"
}

GOGO_DIR="$(dep_dir github.com/cosmos/gogoproto)"
SDK_DIR="$(dep_dir github.com/cosmos/cosmos-sdk)"
COSMOSPROTO_DIR="$(dep_dir github.com/cosmos/cosmos-proto)"

for d in "$GOGO_DIR" "$SDK_DIR/proto" "$COSMOSPROTO_DIR/proto"; do
  [ -d "$d" ] || { echo "include path missing: $d — run 'go mod download' first" >&2; exit 1; }
done

GOGO_VERSION="$(go list -m -f '{{.Version}}' github.com/cosmos/gogoproto)"
echo "==> protoc-gen-gocosmos @ ${GOGO_VERSION}"
go install "github.com/cosmos/gogoproto/protoc-gen-gocosmos@${GOGO_VERSION}"
export PATH="$(go env GOPATH)/bin:${PATH}"

# Generate into a scratch tree first. The plugin writes to the full go_package
# path (github.com/cosmos/evm/evmd/...), so generating in place would create
# that directory inside the module.
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "==> generating"
# One invocation PER DIRECTORY, not one for everything.
#
# The plugin refuses a batch spanning two go_package values —
# "inconsistent package import paths" — and each proto directory here maps to
# its own module's types package. Looping is not a workaround for that error;
# it is the shape the tool expects, and it is what the SDK's own generator
# does.
proto_dirs="$(find proto -name '*.proto' -print0 | xargs -0 -n1 dirname | sort -u)"
for dir in $proto_dirs; do
  echo "    $dir"
  find "$dir" -maxdepth 1 -name '*.proto' -print0 | xargs -0 protoc \
    -I proto \
    -I "$GOGO_DIR" \
    -I "$SDK_DIR/proto" \
    -I "$COSMOSPROTO_DIR/proto" \
    --gocosmos_out="plugins=grpc,Mgoogle/protobuf/any.proto=github.com/cosmos/cosmos-sdk/codec/types:${OUT}"
done

echo "==> placing"
# Copy only this module's own output. Anything the plugin emits under another
# module path belongs to a dependency and must not be written into our tree.
if [ -d "$OUT/github.com/cosmos/evm/evmd" ]; then
  cp -r "$OUT/github.com/cosmos/evm/evmd/." .
else
  echo "no output under github.com/cosmos/evm/evmd — check go_package in the .proto files" >&2
  exit 1
fi

echo "==> done. If 'git status' shows existing .pb.go modified, the committed Go had drifted from the .proto."
