#!/usr/bin/env bash
# Render an mmark Internet-Draft to HTML next to its source.
# Usage: pnpm docs:render [path/to/draft.md]   (default: the composite-proofs draft)
#
# The committed *.html is a generated artifact — edit the *.md, then re-run this.
# The draft's `date` is pinned in its front matter so the render is reproducible;
# with a fixed date, mmark + xml2rfc emit byte-identical HTML every run.
set -euo pipefail

# xml2rfc is installed as a uv tool in ~/.local/bin, which is not on a
# non-login shell's PATH (which is what pnpm gives this script).
export PATH="$PATH:$HOME/.local/bin"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$ROOT/docs/draft-credkit-composite-proofs.md}"

if [ ! -f "$SRC" ]; then
  echo "render-draft: no such file: $SRC" >&2
  exit 1
fi

missing=""
command -v mmark   >/dev/null 2>&1 || missing="$missing mmark"
command -v xml2rfc >/dev/null 2>&1 || missing="$missing xml2rfc"
if [ -n "$missing" ]; then
  cat >&2 <<EOF
render-draft: missing tool(s):$missing

Install once (macOS):
  brew install mmark          # markdown -> xml2rfc XML
  uv tool install xml2rfc     # XML -> Internet-Draft HTML/text
EOF
  exit 1
fi

OUT="${SRC%.md}.html"
# Name the intermediate XML after the draft, in a temp dir: xml2rfc embeds the
# XML's basename as an "alternate" link in the HTML, so a random temp name would
# make every render differ. A stable name keeps the output byte-reproducible.
NAME="$(basename "${SRC%.md}")"
WORK="$(mktemp -d)"
XML="$WORK/$NAME.xml"
trap 'rm -rf "$WORK"' EXIT

mmark "$SRC" > "$XML"
xml2rfc --html "$XML" -o "$OUT"
echo "render-draft: wrote $OUT"
