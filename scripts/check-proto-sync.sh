#!/usr/bin/env bash
#
# check-proto-sync.sh — guard against silent drift of the shared alert.proto
# contract between muthur-central and muthur-collector.
#
# The two repos each vendor their own copy of proto/alert.proto. The bodies MUST
# stay byte-identical; only the `option go_package` line legitimately differs
# (it names the per-repo Go import path). This script hashes the proto with that
# line stripped and compares it to the committed expected hash. Any change to a
# message, field, or field number flips the hash and fails CI — forcing a
# deliberate, reviewable bump that must be mirrored in the sibling repo.
#
# Workflow when you intentionally change the contract:
#   1. Edit proto/alert.proto and regenerate proto/alert.pb.go.
#   2. Run: ./scripts/check-proto-sync.sh --update   (rewrites the .sha256)
#   3. Apply the SAME edit + the SAME new hash to the other repo.
#   4. Release both repos together — never one ahead of the other.
set -euo pipefail

cd "$(dirname "$0")/.."

PROTO="proto/alert.proto"
EXPECTED_FILE="proto/alert.proto.sha256"

normalized_hash() {
  grep -v 'option go_package' "$PROTO" | shasum -a 256 | cut -d' ' -f1
}

actual="$(normalized_hash)"

if [[ "${1:-}" == "--update" ]]; then
  printf '%s  proto/alert.proto (normalized: go_package stripped)\n' "$actual" > "$EXPECTED_FILE"
  echo "updated $EXPECTED_FILE -> $actual"
  exit 0
fi

if [[ ! -f "$EXPECTED_FILE" ]]; then
  echo "ERROR: $EXPECTED_FILE missing. Run: $0 --update" >&2
  exit 1
fi

expected="$(cut -d' ' -f1 < "$EXPECTED_FILE")"

if [[ "$actual" != "$expected" ]]; then
  echo "ERROR: proto/alert.proto has drifted from the recorded contract hash." >&2
  echo "  expected: $expected" >&2
  echo "  actual:   $actual" >&2
  echo "If this change is intentional, run '$0 --update' and mirror the edit +" >&2
  echo "the new hash into the sibling repo (muthur-collector / muthur)." >&2
  exit 1
fi

echo "proto contract OK ($actual)"
