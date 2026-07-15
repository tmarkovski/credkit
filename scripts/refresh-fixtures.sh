#!/usr/bin/env bash
# Re-pull blind BBS fixtures from the spec repo and update the recorded pin.
# The spec is actively churning (-04 in progress). Re-pin deliberately, never silently:
# read the diff before committing.
set -euo pipefail
REPO="https://github.com/cfrg/draft-irtf-cfrg-bbs-blind-signatures.git"
DEST="packages/bbs/test/fixtures"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git clone -q --depth 1 "$REPO" "$TMP/spec"
SHA="$(git -C "$TMP/spec" rev-parse HEAD)"
rm -rf "$ROOT/$DEST"
cp -R "$TMP/spec/fixtures/fixture_data" "$ROOT/$DEST"
cp "$TMP/spec/draft-irtf-cfrg-bbs-blind-signatures.md" "$ROOT/docs/spec-blind-bbs-snapshot.md"
echo "$SHA" > "$ROOT/packages/bbs/test/fixtures/.spec-sha"
echo "fixtures now pinned to $SHA"
echo "review 'git diff' before committing — a vector change may mean the spec changed under you"
