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
| `GET /verify?token=…` | The confirm-address page a verification link opens. Never reads the token |
| `POST /verify` | `{ token }` (JSON) or the page's own form. Sets `primary_email_verified`. Answer: `200`, or one refusal |
| `POST /verify/resend` | `{ email }`. Always `202`, always the same body. Mails a link only to an existing, unverified account |
| `GET /reset?token=…` | The choose-a-new-password page a reset link opens. Never reads the token |
| `POST /reset` | `{ token, new_password }` (JSON) or the page's own form. Sets the password, clears the lockout, revokes every session and refresh token |
| `GET /reset/request` | The "forgot your password" form, the page a duplicate-registration mail points at |
| `POST /reset/request` | `{ email }`. Always `202`, always the same body. Mails a link only to an account that has a password |

The sign-in and recovery routes — `POST /start`, `POST /login`,
`POST /change`, `POST /verify`, `POST /reset`, `POST /verify/resend` and
`POST /reset/request` — refuse a cross-site request: a `sec-fetch-site`
or `Origin` naming another site answers `403` (`auth/cross-site-request`)
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
| `AUTH_PASSWORD_PUBLIC_BASE` | *(unset)* | The origin a mailed link points at. Unset means this deployment sends no recovery mail |
| `AUTH_PASSWORD_MAIL_FROM` | *(unset)* | The `From` address on that mail. Unset means the same |

`PUBLIC_BASE` and `MAIL_FROM` are both optional, and so is the `Mailer`
port — a venture that mounts `Password` on its own keeps booting with no
mail configured. `register`, `login` and `change` work exactly as before;
only the verification and reset mail is switched off, and those endpoints
still answer `202`. Setting `PUBLIC_BASE` to something that is not `https`
(a `http://localhost` link is allowed for `wrangler dev`) is a
`validate_config` failure rather than a link that points nowhere.

Ten failures is far above a person mistyping and far below a useful
guessing rate. Fifteen minutes is long enough to make guessing pointless
and short enough that somebody whose only login method is a password is
not stuck for the day.

Nonsense in any of these is a `validate_config` failure rather than a
silent fall back to the default — though note that nothing on the
production boot path calls `validate_config`
([Cratefield/harness#101](https://github.com/Cratefield/harness/issues/101)),
so today that means `cargo test` catches it.

## The locale a registration records

`POST /register` accepts an optional `locale` alongside `email` and
`password`. When it names a tag the deployment supports it is stored on the
account; when it does not, the column stays null and the account inherits
whatever a later request resolves. A regional tag matches by language, so a
supported `de` takes `de-AT` and stores the canonical `de`.

`AUTH_LOCALES` lists the supported tags, comma-separated in BCP 47 form,
the first being the default (`AUTH_LOCALES=de,en`). It is a deployment-wide
key rather than an `AUTH_PASSWORD_` one: every auth module reads it, and
the same list is what `cratefield-auth-magic-link` resolves its sign-in mail
from. Unset, the deployment supports `en`.

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

## Rate limits

This crate owns the key strings and the 429 behaviour, not the numbers.
Quotas are enforced by the harness `RateLimiter` adapter and set in the
instance's deployment config; keys are `auth-password:{key}` over
`rate_limit_keys(ip, email)`, i.e. one per-IP bucket and one per
normalised-email bucket. In-memory adapters are per-isolate, so a
multi-isolate deployment needs a KV-backed limiter. Every refusal is
`429` with a `Retry-After`.

| Scope | Recommended quota | Why |
|---|---|---|
| Login per IP | 10/min | A person mistypes a few times; a guesser needs thousands. 10/min fits the former and is noise against Argon2id, while staying loose enough for an office or campus behind one NAT address. |
| Login per normalised email, any IP | 5/15min | The per-IP bucket does nothing against a botnet guessing one account from many addresses. The email bucket is what catches that: 5 per 15 minutes still tolerates real mistyping but caps distributed guessing at under 500 tries a day per account, before the lockout below even matters. |
| Lockout | 10 failures in an hour, frozen 15 minutes | Owned here (`AUTH_PASSWORD_LOCKOUT_*`, env-overridable, min-clamped). Ten is far above mistyping and far below a useful guessing rate; fifteen minutes makes guessing pointless without stranding somebody whose only login method is a password for the day. |
| Registration and password change per IP | Same bucket policy as login | No separate number is set for these, so use the login one: both are anonymous (registration) or low-frequency (change) writes with the same abuse shape, and one knob is easier to operate than three. |

The lockout freezes the **password**, not the person: passkey, OIDC and
magic-link sign-ins still work during it (see
`../auth-magic-link/README.md` for the way back in). Nothing clears the
lockout row except wall-clock expiry and a successful password
login/change — an alternative-method sign-in bypasses the freeze, it
does not lift it.

Captcha, where the port is present, is required on login (and on
magic-link request): verification failure refuses the request rather
than letting it through, so a captcha outage fails closed.

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

## Verifying an address, and getting back in

Two single-use bearer credentials go out by mail — a verification link
(24 hours) and a reset link (30 minutes). Both are stored the way a magic
link is: only the SHA-256 digest is written down, so a leaked
`single_use_tokens` row is not a way in, and the token itself is never
logged. Issuing a second link retires the first, so the newest one wins.

**The link asks; only the button acts.** A mail scanner fetches every URL
in a message, so `GET /verify` and `GET /reset` never read or spend the
token — they render a form whose same-origin `POST` does the work. The
`POST` accepts JSON (the API) or the form (the hosted page), and answers
in the shape it was asked for. Missing, expired, already-used,
never-issued and wrong-kind tokens all answer with one refusal
(`auth/password-token-refused`), and the refusal says nothing about which
account, if any, a token was for.

`POST /verify/resend` and `POST /reset/request` are rate-limited and
captcha-guarded like `/login`, and answer `202` with the same body
whether the address has an account or not — a reset mail goes out only
when the account has a password credential, and a verification mail only
when the address exists and is unverified. Both take the same two body
shapes as the token endpoints: JSON from an API caller, and
`application/x-www-form-urlencoded` from the hosted `/reset/request`
form, which is what that page posts. `/register` mails the
verification link to a new address and a duplicate-registration notice to
an existing one — including a magic-link-only account — and the body it
returns is identical either way.

The mail itself is handed to the request's `Defer` port and sent after
the response, the way every other module that mails does it, so a caller
never waits on a delivery to be told `202`. An address
`cratefield_core::is_valid` refuses — control characters, spaces, no `@` —
is still answered `202`, and simply has no mail sent to it.

A reset is what somebody does when they think their password is known to
others, so it changes the hash and revokes **every** session and refresh
token the account has; it also clears the lockout, because proving the
reset is proving the credential. The person is not signed in afterwards.
A password the policy refuses is rejected before the token is spent, so a
too-short attempt does not cost them the link. `POST /change` does the
same for a signed-in person, and retires any reset link their account has
out as well — otherwise a link somebody else had asked for would undo the
change they just made.

Every page here — the confirm page, the reset form, the request form and
the page a form `POST` answers with — carries `Cache-Control: no-store`
and `Referrer-Policy: no-referrer`. A token arrives in a URL, and a URL
must not sit in a shared cache or ride along as a `Referer`.

### Mail templates

Rendered through the shared template registry, overridable per locale like
any other module's mail:

| Id | Sent when |
|---|---|
| `auth-password/verify` | A new address needs confirming |
| `auth-password/duplicate` | Somebody tried to register an address that already has an account |
| `auth-password/reset` | An account with a password asked to reset it |

The request body may carry a `locale` (a BCP 47 tag such as `en-GB`;
anything else falls back to `en`).

### Events

`auth-password.email_verified` and `auth-password.reset` each carry
`user_id` and nothing else — never an address, the same rule every other
event in the stack follows.

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

- A subscriber that needs the address behind an event **has to look it up**
  from the `user_id` in the payload. That is deliberate: see below. An
  address can change, and the copy in an old event would be the stale one.
- Mail is rendered in the locale the request names, defaulting to `en`.
  There is no negotiation from `Accept-Language`: the hosted page's form
  and the JSON API both pass the locale they want, and a locale only
  changes the mail if a corresponding `<id>@<locale>` override is
  registered.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
