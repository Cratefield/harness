#!/usr/bin/env bash
# Regenerates assets/readme-banner.png from tools/banner-render.html with headless Chrome
# (ImageMagick cannot rasterize the canvas + web fonts). Rendered at 2x for retina.
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$1"; }
K="${BANNER_KICKER:-FACTORY ZER{o} · FZ/01}"; T="${BANNER_TITLE:-API.FACTORY0.VENTURES}"; S="${BANNER_SUB:-The first venture backend built on the harness.}"; M="${BANNER_META:-EMAIL SIGNUP · WAITLIST · CLOUDFLARE D1}"; SEED="${BANNER_SEED:-7}"
"$CHROME" --headless --disable-gpu --no-sandbox --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1280,400 --virtual-time-budget=10000 --screenshot="assets/readme-banner.png" \
  "file://$PWD/tools/banner-render.html?k=$(urlenc "$K")&t=$(urlenc "$T")&s=$(urlenc "$S")&m=$(urlenc "$M")&seed=$SEED" >/dev/null 2>&1
echo "assets/readme-banner.png $(sips -g pixelWidth -g pixelHeight assets/readme-banner.png | tail -2 | tr -d ' \n')"
