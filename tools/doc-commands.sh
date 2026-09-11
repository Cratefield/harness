#!/usr/bin/env bash
# Runs the shell commands the documentation tells a reader to run (issue #146).
#
# Why this exists: a documented command that rots is caught here, by CI,
# instead of by the next reader. Two guarantees carry that:
#
# 1. The commands are extracted from the markdown mechanically. Nothing in
#    this script retypes a command from the prose — it evals the exact fence
#    content, so the prose and the tested thing cannot drift apart.
# 2. Every fenced block in the covered files must be classified below. A new
#    block added to a covered file fails this script until someone says what
#    it is — run it here, point at the CI job that already runs it, or record
#    why it cannot run without a human (Cloudflare dashboard, deploy,
#    credentials). A block nobody classified is a command nobody tested.
#
# Covered files: the README and the getting-started path
# (docs/VENTURE-GUIDE.md). Other docs' commands can be added to DOC_FILES.
#
# Fences are classified by `registry`, keyed `file:ordinal` (ordinal counts
# every ``` fence in the file, top to bottom). Actions:
#   run:shell:<dir>        — eval the fence verbatim from <dir>.
#   run:dollar:<dir>       — prose fences that paste a session (output under
#                            a `$ ` prompt): eval only the `$ ` command lines
#                            and their continuations, dropping pasted output.
#   run:server:<dir>       — like run:dollar, for the fence that starts the
#                            dev server: placeholder lines are recorded and
#                            skipped, the `wrangler dev` line is eval'd in
#                            the background once its /__health answers, and
#                            the server stays up for later fences (killed
#                            when the script exits).
#   skip:<why>             — recorded reason; printed, not run.
# Unknown key, empty reason, or a failing command fails the script.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

DOC_FILES=(
  "README.md"
  "docs/VENTURE-GUIDE.md"
)

fail=0
devlog="$(mktemp)"
fzventure="$root/crates/cli-acceptance/.doc-cmds-fixture"
cleanup() {
  pkill -f 'wrangler dev --local --port 8792' 2>/dev/null
  rm -rf "$fzventure"
  rm -f "$devlog"
}
trap cleanup EXIT

# Extract fences: emits `===<file>:<ordinal>` then the fence body, per fence.
# Fences inside list items are indented; the opener test must match those too.
extract_fences() {
  local file="$1" ordinal=0 in_fence=0
  while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    if [[ "$trimmed" == '```'* ]]; then
      if (( in_fence )); then
        in_fence=0
      else
        in_fence=1
        ordinal=$((ordinal + 1))
        echo "===${file}:${ordinal}"
      fi
      continue
    fi
    (( in_fence )) && printf '%s\n' "$line"
  done < "$file"
}

# Strip pasted output from a `$ `-prompted fence, keeping command lines and
# their backslash continuations / indented argument lines.
dollar_commands() {
  awk '
    /^[[:space:]]*\$ / {
      sub(/^[[:space:]]*\$ /, "")
      keep = 1
      print
      next
    }
    keep && /\\$/ { print; next }
    keep && /^[[:space:]]+[^$[:space:]]/ { print; next }
    { keep = 0 }
  '
}

registry() {
  case "$1" in
    # ---- README.md -------------------------------------------------------
    README.md:1) echo "skip:rust composition example, not a command" ;;
    README.md:2) echo "skip:mermaid diagram, not a command" ;;
    README.md:3) echo "skip:toml dependency example, not a command" ;;
    README.md:4) echo "skip:rust Module trait, not a command" ;;
    README.md:5) echo "skip:needs a deployed Worker and wrangler auth (Cloudflare account)" ;;
    README.md:6) echo "skip:fmt/clippy/test/worker-build, each already gated by the ci.yml fmt, clippy, test and wasm jobs" ;;
    README.md:7) echo "skip:repo layout listing, not a command" ;;
    # ---- docs/VENTURE-GUIDE.md --------------------------------------------
    docs/VENTURE-GUIDE.md:1)
      # Prerequisites: idempotent installs.
      echo "run:shell:$root"
      ;;
    docs/VENTURE-GUIDE.md:2) echo "skip:template file tree, not a command" ;;
    docs/VENTURE-GUIDE.md:3) echo "skip:rust composition example, not a command" ;;
    docs/VENTURE-GUIDE.md:4) echo "skip:cargo test of a venture — examples/venture compiles under cargo test --workspace" ;;
    docs/VENTURE-GUIDE.md:5)
      # The guide's "migrations first, then dev" fence. Its apply line
      # carries a <database-name> placeholder (the concrete run is block 7);
      # the dev line is the one this script starts the server from for
      # blocks 6–9.
      echo "run:server:$root/examples/venture"
      ;;
    docs/VENTURE-GUIDE.md:6) echo "run:dollar:$root/examples/venture" ;;
    docs/VENTURE-GUIDE.md:7) echo "run:dollar:$root/examples/venture" ;;
    docs/VENTURE-GUIDE.md:8) echo "run:dollar:$root/examples/venture" ;;
    docs/VENTURE-GUIDE.md:9) echo "run:dollar:$root/examples/venture" ;;
    docs/VENTURE-GUIDE.md:10) echo "skip:human step: wrangler d1 create needs an authenticated Cloudflare account" ;;
    docs/VENTURE-GUIDE.md:11) echo "skip:toml snippet, not a command" ;;
    docs/VENTURE-GUIDE.md:12)
      # The prose runs `cargo run --bin fz` from "the venture repo" — the
      # template wires fz as a bin target. The fixture copy is that repo;
      # examples/venture has no bin target by design (wasm canary).
      echo "run:shell:fzventure"
      ;;
    docs/VENTURE-GUIDE.md:13) echo "skip:placeholder <venture>-api args; the local half ran as block 7, the remote half needs wrangler auth" ;;
    docs/VENTURE-GUIDE.md:14) echo "skip:placeholder args; remote apply needs wrangler auth" ;;
    docs/VENTURE-GUIDE.md:15) echo "skip:pasted d1_migrations table, not a command" ;;
    docs/VENTURE-GUIDE.md:16) echo "skip:pasted re-applied-migration illustration, not a command" ;;
    docs/VENTURE-GUIDE.md:17)
      # Local, credential-free half of the VAPID recipe. keygen refuses to
      # overwrite an existing file, so it gets a fresh directory.
      echo "run:shell:tmpdir"
      ;;
    docs/VENTURE-GUIDE.md:18) echo "skip:human step: wrangler secret put needs an authenticated Cloudflare account" ;;
    docs/VENTURE-GUIDE.md:19) echo "skip:html embed snippet, not a command" ;;
    docs/VENTURE-GUIDE.md:20) echo "skip:placeholder URLs against a deployed venture" ;;
    *)
      echo "FAIL: unclassified doc fence $1 — classify it in registry() in tools/doc-commands.sh (run it, name the CI job that already runs it, or record why a human must)"
      fail=1
      ;;
  esac
}

# The dev-server fence: skip placeholder lines, background the wrangler dev
# line once /__health answers, leave it running for later fences.
run_server_fence() {
  local dir="$1" body="$2" cmds port="" script
  cmds="$(printf '%s\n' "$body" | dollar_commands)"
  if [[ -z "$cmds" ]]; then
    echo "FAIL: run:server but no \$-prompted command was found"
    fail=1
    return
  fi
  script="$(mktemp)"
  while IFS= read -r line; do
    if [[ "$line" == *'<database-name>'* ]]; then
      # Diagnostics go to stderr: this loop's stdout IS the generated script.
      echo "     skip placeholder line: $line" >&2
    elif [[ "$line" == *"wrangler dev"* ]]; then
      port="$(grep -oE -- '--port [0-9]+' <<<"$line" | awk '{print $2}')"
      if [[ -z "$port" ]]; then
        echo "FAIL: wrangler dev line has no --port to poll: $line"
        fail=1
        return
      fi
      echo "if curl -sf -m 3 http://127.0.0.1:$port/__health >/dev/null 2>&1; then"
      echo "  echo 'something is already serving on port $port — the doc port must be free'"
      echo "  exit 1"
      echo "fi"
      echo "nohup $line > '$devlog' 2>&1 &"
      echo "for _ in \$(seq 1 60); do"
      echo "  curl -sf -m 3 http://127.0.0.1:$port/__health >/dev/null 2>&1 && break"
      echo "  sleep 2"
      echo "done"
      echo "curl -sf -m 3 http://127.0.0.1:$port/__health >/dev/null || { echo 'server never became ready'; cat '$devlog'; exit 1; }"
    else
      printf '%s\n' "$line"
    fi
  done <<<"$cmds" > "$script"
  echo "---- run (server fence) in $dir"
  cat "$script"
  ( cd "$dir" && bash "$script" )
}

run_block() {
  local mode="$1" dir="$2" body="$3"
  if [[ "$dir" == "tmpdir" ]]; then
    dir="$(mktemp -d)"
  elif [[ "$dir" == "fzventure" ]]; then
    # A fresh copy of the fixture venture: the prose runs `cargo run --bin
    # fz` from "the venture repo", and the fixture is this repository's
    # stand-in for one (bin target wired, path deps relative). collect
    # writes migrations, so it runs against the copy, never the original.
    rm -rf "$fzventure"
    cp -R crates/cli-acceptance/fixture "$fzventure"
    dir="$fzventure"
  fi
  if [[ "$mode" == "server" ]]; then
    run_server_fence "$dir" "$body"
    return
  fi
  echo "---- run in $dir"
  if [[ "$mode" == "dollar" ]]; then
    local cmds
    cmds="$(printf '%s\n' "$body" | dollar_commands)"
    if [[ -z "$cmds" ]]; then
      echo "FAIL: run:dollar but no \$-prompted command was found"
      fail=1
      return
    fi
    echo "$cmds"
    ( cd "$dir" && eval "$cmds" )
  else
    printf '%s\n' "$body"
    ( cd "$dir" && eval "$body" )
  fi
}

for file in "${DOC_FILES[@]}"; do
  [[ -f "$file" ]] || { echo "FAIL: covered doc file $file is gone"; exit 1; }
done

# The `fz` binary stands in for the template's venture-side bin target
# (guide step 4). The fixture package carries exactly that bin; the cli
# crate itself has none, so `cargo install --path crates/cli` is a trap.
command -v fz >/dev/null 2>&1 || cargo install --path crates/cli-acceptance/fixture --bin fz --locked -q

blocks_file="$(mktemp)"
# Blocks are joined with a marker line, not a NUL byte: the awk on macOS
# (BWK) drops "\0" from printf output entirely, which once made this loop
# read a single unterminated record and classify nothing — a vacuous green.
for file in "${DOC_FILES[@]}"; do
  extract_fences "$file"
done | awk '
  /^===/ { if (buf != "") { print buf; print "@@FENCE_END@@" } ; buf = $0; next }
  { buf = buf "\n" $0 }
  END { if (buf != "") print buf }
' > "$blocks_file"

classify_block() {
  local block="$1" key body first action mode dir
  key="${block%%$'\n'*}"     # ===file:ordinal
  key="${key#===}"
  body="${block#*$'\n'}"
  first="${body%%$'\n'*}"
  echo ""
  echo "== $key   first line: $first"
  action="$(registry "$key")"
  case "$action" in
    skip:*) echo "     skip: ${action#skip:}" ;;
    run:shell:*|run:dollar:*|run:server:*)
      mode="${action#run:}"; mode="${mode%%:*}"
      dir="${action#run:${mode}:}"
      run_block "$mode" "$dir" "$body" || fail=1
      ;;
    *) echo "FAIL: registry returned a malformed action for $key"; fail=1 ;;
  esac
}

classified=0
block=""
while IFS= read -r line; do
  if [[ "$line" == '==='* ]]; then
    if [[ -n "$block" ]]; then
      classify_block "$block"
      (( classified++ ))
    fi
    block="$line"
  elif [[ "$line" == '@@FENCE_END@@' ]]; then
    classify_block "$block"
    (( classified++ ))
    block=""
  else
    block="$block"$'\n'"$line"
  fi
done < "$blocks_file"
if [[ -n "$block" ]]; then
  classify_block "$block"
  (( classified++ ))
fi
if (( classified == 0 )); then
  echo "FAIL: no doc fences were extracted — the extractor broke"
  exit 1
fi

if (( fail )); then
  echo ""
  echo "doc-commands: FAILED"
  exit 1
fi
echo ""
echo "doc-commands: every documented command ran here, is covered by another CI job, or carries its recorded human-step reason"
