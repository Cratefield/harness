#!/usr/bin/env bash
# Regenerates assets/readme-banner.png from tools/banner-render.html with headless Chrome
# (ImageMagick cannot rasterize the canvas + web fonts). Rendered at 2x for retina.
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$1"; }
K="${BANNER_KICKER:-FACTORY ZER{o} · TEMPLATE}"; T="${BANNER_TITLE:-VENTURE BACKEND}"; S="${BANNER_SUB:-From template to production in under thirty minutes.}"; M="${BANNER_META:-GITHUB TEMPLATE · RUST · ONE WORKER PER VENTURE}"; SEED="${BANNER_SEED:-5}"
"$CHROME" --headless --disable-gpu --no-sandbox --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1280,400 --virtual-time-budget=10000 --screenshot="assets/readme-banner.png" \
  "file://$PWD/tools/banner-render.html?k=$(urlenc "$K")&t=$(urlenc "$T")&s=$(urlenc "$S")&m=$(urlenc "$M")&seed=$SEED" >/dev/null 2>&1
echo "assets/readme-banner.png $(sips -g pixelWidth -g pixelHeight assets/readme-banner.png | tail -2 | tr -d ' \n')"
