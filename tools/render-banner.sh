#!/usr/bin/env bash
# Regenerates assets/readme-banner.png and assets/social-preview.png from
# tools/banner-render.html with headless Chrome (ImageMagick cannot rasterize
# the web fonts). The README banner is rendered at 2x for retina.
#
# GitHub has no API for a repository's social preview image: upload
# assets/social-preview.png by hand at
# github.com/Cratefield/harness/settings -> Social preview.
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$1"; }

K="${BANNER_KICKER:-CRATEFIELD · HARNESS · OPEN SOURCE}"
T="${BANNER_TITLE:-The open-source core.}"
S="${BANNER_SUB:-Modules are crates. They compile at build time into one stateless Worker with its own database.}"
M="${BANNER_META:-RUST · WASM32 · MODULES AS CRATES · ONE DATABASE PER TENANT}"

shoot() { # height out scale
  "$CHROME" --headless --disable-gpu --no-sandbox --hide-scrollbars \
    --force-device-scale-factor="$3" --window-size="1280,$1" \
    --virtual-time-budget=10000 --screenshot="$2" \
    "file://$PWD/tools/banner-render.html?h=$1&k=$(urlenc "$K")&t=$(urlenc "$T")&s=$(urlenc "$S")&m=$(urlenc "$M")" >/dev/null 2>&1
}

shoot 400 assets/readme-banner.png 2
shoot 640 assets/social-preview.png 1

for f in readme-banner.png social-preview.png; do
  printf '%-22s %s\n' "assets/$f" "$(sips -g pixelWidth -g pixelHeight "assets/$f" | tail -2 | tr -d ' \n')"
done
