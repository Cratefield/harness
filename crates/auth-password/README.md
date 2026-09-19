# auth-password

Email and password (issues #12, #19, #20). Mounted at `/v1/auth-password`.

The oldest login method and the only one where a stranger can simply keep
guessing, which is what most of this crate is about.

## It requires the paid Workers plan

ADR 0200 measured Argon2id at the parameters this uses (m=19456, t=2, p=1)
at roughly **40 ms per hash or verify** on Workers. The free tier's 10 ms
CPU limit cannot fit one verify at any sane parameters.

That is a deployment fact rather than a tuning knob: lowering the
parameters to fit the free tier would make the stored hashes worth less
than not having them.

## Routes

| Route | What it does |
|---|---|
| `POST /register` | `{ email, password }`. Always `202`, always the same body |
| `POST /login` | `{ email, password }`. A session cookie, or one refusal |
| `GET /start?return_to=/path` | The form, for the login chooser |
| `POST /start` | The form's own target. Same decision as `/login`, answered with a page |
| `POST /change` | `{ current_password, new_password }`, for a signed-in person |

The three sign-in routes — `POST /start`, `POST /login` and
`POST /change` — refuse a cross-site request: a `sec-fetch-site` or
`Origin` naming another site answers `403` (`auth/cross-site-request`)
before anything else happens. Signing in sets a session cookie, and
`SameSite=Lax` stops a cross-site POST from *carrying* our cookie, not
from *setting* one (issue #439). `POST /register` issues no session, so
a cross-site POST there has nothing to steal.

### Why this method is a page

The login chooser at `/v1/auth-core/authorize` renders a link, which is
how every provider method works, or a button that starts a WebAuthn
ceremony in script, which is how passkeys work. This method is neither:
two fields have to be typed, and a wrong password has to be answerable on
the page it was typed into. So the module serves its own form at `/start`
and the chooser links to it, the same shape `auth-magic-link` uses.

`POST /start` and `POST /login` both go through one `sign_in`, so the page
cannot grow a second set of rules about who may sign in. In particular the
failure counter is one credential row: ten wrong passwords typed into the
form lock the account against the JSON route too, which
`the_page_and_the_json_route_share_one_lockout` is there to hold.

A success is `303` to `return_to` with the session cookie attached,
because a browser that has just posted a password should land somewhere
rather than read JSON. `return_to` is checked before it becomes a
`Location` — an absolute URL there would be an open redirect handing a
fresh session cookie to whoever asked — and escaped before it goes back
into the form's hidden field.

Plain HTML, no script. The `autocomplete` pair (`username` and
`current-password`) is what lets a password manager fill it.

Enable it with `password` in `AUTH_CORE_LOGIN_METHODS`.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `AUTH_PASSWORD_BREACH_CHECK` | `true` | Ask the Pwned Passwords range API about a new password |
| `AUTH_PASSWORD_LOCKOUT_THRESHOLD` | `10` | Failures in the window before the password locks |
| `AUTH_PASSWORD_LOCKOUT_WINDOW_SECS` | `3600` | The window failures are counted in |
| `AUTH_PASSWORD_LOCKOUT_SECS` | `900` | How long a lock lasts |

Ten failures is far above a person mistyping and far below a useful
guessing rate. Fifteen minutes is long enough to make guessing pointless
and short enough that somebody whose only login method is a password is
not stuck for the day.

Nonsense in any of these is a `validate_config` failure rather than a
silent fall back to the default — though note that nothing on the
production boot path calls `validate_config`
([Cratefield/harness#101](https://github.com/Cratefield/harness/issues/101)),
so today that means `cargo test` catches it.

## Three defences, and they are not the same defence

**The `RateLimiter` port** is keyed on the request. It slows one attacker
down and does nothing about one with a botnet. Keys include the normalised
address as well as the caller, so a distributed guess against one account
is still limited.

**The lockout** is keyed on the credential, so it survives an attacker
rotating IP addresses. It locks the **password**, not the account:
somebody locked out here can still sign in with a passkey or a provider,
which is what keeps the lockout from being a denial of service an attacker
can aim at a person by guessing wrongly on purpose.

**The `Captcha` port**, where a deployment provides one, is what makes the
first two expensive to reach. Not required — a module that refused to
start without a captcha would take the whole service down — but `fz
doctor` refuses a production venture with public writes and no captcha.

## Events carry ids, never an address

Every event this module emits carries `user_id` and, where it applies,
`session_id` — the same shape as every other event in the auth stack. Two
of them used to carry the address as well, for a subscriber's convenience,
and that made them the only events in the stack that did.

A payload does not stay inside the service. It goes to the event
forwarder, which on the sidecar path is a separate Worker. So
`duplicate_registration` was carrying "this address has an account" — the
exact fact the `202` from `/register` is built not to reveal — out of the
service, attached to the address it is about.

A subscriber that needs the address looks it up with `user_by_id`, which
it would have to do anyway: an address can change, and the copy in an old
event would be the stale one. `no_event_this_module_emits_carries_an_address`
pins it, and also asserts the payload still names somebody, because an
empty payload would satisfy the first half and be useless.

## Nothing here says whether an address has an account

- **Registration** answers `202` and the same body whether it created an
  account, found the address already registered, or was handed something
  that is not an address. The owner of an already-registered address is
  told by mail, through the `auth-password.duplicate_registration` event;
  the person at the keyboard learns nothing.
- **Login** answers identically for a wrong password, an unknown address,
  a disabled account and a locked one.
- **The timing does not answer either.** An unknown address is verified
  against a fixed dummy hash, so it costs the same Argon2id verify a real
  one does. Skipping that is how a "constant-time" login leaks anyway.

The one thing registration *does* say is that a password is unusable, and
only ever about the password in front of it: too short, too long, or in a
breach corpus. Refusing silently would leave somebody unable to sign in
later, and none of it reveals anything about anybody else.

## The breach check

Pwned Passwords k-anonymity: the first five hex characters of the SHA-1 go
to the range API, every suffix sharing that prefix comes back, and the
comparison happens here. **The password and its full hash never leave.**
SHA-1 is the corpus's index, not a security choice.

**Fail-open, deliberately.** A corpus that is unreachable is not a reason
to stop people registering: the alternative turns somebody else's outage
into ours, and the check is advice rather than authentication.

## Rehash on login

Login is the only moment the plaintext exists, so it is the only moment a
stored hash written at older parameters can be upgraded. A hash that
cannot be parsed is left alone: it will fail verification anyway, and
rehashing on the strength of an unreadable value would be guessing.

## Known gaps

- **The address is never verified here.** A new account is
  `primary_email_verified = 0`, and only a magic link (#21) can change
  that. The linking rules only auto-link a verified address, so registering
  must not be a way to claim one.
- **No account recovery.** Somebody who forgets their password has no way
  back in through this module; that is the magic link's job. The form at
  `/start` does not link to it either: this module cannot know whether
  `auth-magic-link` is mounted, and a "forgot your password?" link to a
  404 is worse than none.
- The `auth-password.duplicate_registration` event says a mail should be
  sent. **Nothing sends it yet** — no mail module subscribes, so today the
  owner of an already-registered address is told nothing at all.
- A subscriber, when there is one, **has to look the address up** from the
  `user_id` in the payload. That is deliberate: see below.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
