# Brief: issue #190 — multi-language notifications

Build Cratefield/harness issue **#190** in `/Users/nick/Documents/GitHub/fz-work/notif-i18n` on branch `feat/notif-i18n`. Read it in full: `gh issue view 190 -R Cratefield/harness`.

All three channels are merged — push, the in-app inbox, and email. This makes them speak the recipient's language. **Read the merged module's `notify`, its drain and its preference table first**: this extends them, and the issue's design assumed a shape that has since been built, so check rather than assume.

## The core idea

The language cannot be chosen when the caller queues the notification, because one account can have an English browser and an Indonesian phone. It is resolved **per recipient at delivery**: the subscription's locale, then the account's, then the venture's default.

## Things the issue records that are easy to get wrong

- **The default `FluentBundle` is neither `Send` nor `Sync`** (it is built on `Rc`/`RefCell`), and `SendWrapper` cannot fix that — it grants `Send` alone and panics off-thread. Use the concurrent memoizer, which is `Send + Sync`, and pin it with a static assertion.
- **`unic-langid` carries no text-direction data.** Direction comes from an explicit RTL script/language list in the crate, and is tested.
- **A missing key must be visible**, never silent: render the key and emit an event, with a test.
- Apps that ship their own strings get native localisation keys passed through to APNs and FCM instead of rendered text. Web Push has no such mechanism and is always server-rendered.

Single-language ventures must pay nothing: a caller that passes rendered text keeps working untouched, and that is worth a test of its own.

## Rules

    export PATH=~/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH

- Do NOT merge. Open ONE pull request and stop. Never `git stash`.
- **Another session merges to `main` often.** `git fetch` before you start and
  again before you push; a sibling agent is building the other remaining issue
  right now, so keep your diff to your own.
- **Never edit a migration already on `main`.** New schema goes in a new
  migration, collected into `examples/venture/migrations/` (note `fz migrations
  collect` cannot run for that venture — reproduce the collector's output and
  the guard test confirms it).
- **Never put a value read from the environment, a recipient, or a URL into a
  log, an error, a report or a database column.** This epic leaked a signing
  key, a device token, a push endpoint and a recipient address — every one of
  them through an error string from a layer below the code that promised not to
  leak, and every one with a test that only exercised the success path. Put the
  guarantee at a boundary, not at each call site, and test the failure arm.
- Every behaviour needs a test that fails without it. When you check that by
  reverting in place, restore with a **plain** copy and `touch` the sources — a
  timestamp-preserving copy makes cargo skip the rebuild, so the suite passes
  against a stale binary and proves nothing.
- Run it and report real output. A background task's reported exit status can
  be the wrapper's, not the command's — read the log, not the notification.

    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all --check

Commit trailer:

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01L8yJzMpLZZujnB8nhwEuVG
