# ADR 0028: Inbound mail is a verified source, and the runtime serves a module's surface over MCP

Status: accepted, 2026-10-04. Issue #563. Extends ADR 0002 (ports and
adapters) with an inbound path beside the outbound one, and ADR 0021
(what the MCP server is allowed to be) with a runtime helper. Telephony
and speech are recorded as shape only, and nothing here is implemented
by this ADR beyond core's trait and the Resend adapter.

## Context

Support-style ventures need to **receive** messages, not only send them.
The harness has one direction: `Mailer` sends, and tracker's
`StatusWebhook` is the lone inbound shape, a webhook verified and parsed
per vendor (issue #625). Three things are missing, and only the first is
built now.

**Inbound mail.** A venture that answers a customer needs the message the
customer sent — a reply to a notification, a support thread. Resend,
Cloudflare Email Routing and Postmark all deliver one, each with its own
signature story.

**The runtime as an MCP server.** `cratefield-mcp` wraps `fz --json` over
stdio (ADR 0021). A *module's* `surface()` — the routes it already
declares for the browser — is reachable by an agent only if a server
turns those actions into tools, and a Worker or a native binary can do
that at runtime without a child process.

**Telephony and speech.** A venture that calls or texts needs the same
inbound/outbound shape mail has, and nothing exists for it.

## Decision

**1. Inbound mail is a verify-then-parse trait in core, not a `Port`
variant.** `InboundMailSource` (`crates/core/src/ports/inbound_mail.rs`)
has `kind()`, `verifier() -> WebhookVerifier` and
`parse(&[u8]) -> Result<Option<InboundMessage>, InboundMailError>`;
`receive_mail(source, secret, headers, body, now_unix)` verifies and only
then parses, so `parse` never sees unverified bytes. This is deliberately
tracker's `StatusWebhook`/`receive_status` shape (`receive_status()`,
`InboundStatusError`), not a `Port::InboundMail` variant: an inbound
delivery is *pushed* at a route with a per-endpoint secret, and a
`Port` entry would touch `Port::ALL`, `Ports`, both runtimes and every
bundle for a service a module reaches through a webhook route, never
through `module.ports()`. The outbound `Mailer` stays the port; the
inbound half is its mirror. An adapter hands a parsed `InboundMessage`
to a module — provider id, from, to, cc, subject, optional text/html,
optional headers, optional received-at — the way `Mailer` takes a
`Message` from it.

**2. Verification is core's, dedup is the `Inbox`'s.** `verifier()`
returns a `WebhookVerifier` over a `SignatureScheme`, never a re-derived
HMAC. Resend signs with **Svix** (`Svix`, the scheme Clerk uses),
so `ResendInbound` verifies with no new scheme code. A redelivery is
claimed once through `idempotency::Inbox`, keyed on the provider's
message id (`InboundMessage::event_key()`, `inbound-mail:<id>`), because
a valid signature stops neither a provider retry nor a replay inside the
tolerance.

**3. The Resend adapter ships now; two adapters are follow-ups.** A
Resend webhook is **metadata only** — the `email.received` payload
carries `email_id`, envelopes, subject and attachment metadata, never the
body; the HTML, text and headers are a separate Received-emails API call
(`GET /emails/receiving/{email_id}`). The adapter parses what the webhook
carries and leaves `text`/`html` `None`, documenting the fetch as the
caller's step rather than making a network call inside `parse`.
Follow-ups, both recorded here and neither built:
*Cloudflare Email Workers*, where the Worker `email()` entrypoint hands
over **raw MIME** and needs a MIME parser plus a runtime entrypoint that
routes it into a module; and *Postmark*, whose inbound webhook carries
**no HMAC** — a shared token over `Basic` auth on HTTPS — so it verifies
through the token path rather than a signature, and its weaker replay
story is the module's (`Inbox`) to cover.

**4. The runtime serves a module's `surface()` as MCP tools — designed,
not built.** A new runtime route speaks MCP's Streamable HTTP JSON-RPC,
and the same helper mounts it in **both** runtimes — the Worker and the
native binary — so a tool list does not depend on where the module runs.
Tools map from `Surface` `Action`s: `name` from `Action.name`,
`inputSchema` from `Action.input` (a JSON Schema already), and
`description` synthesised from the action's name, method and path —
`Action` carries no description field today; adding one is part of that
follow-up, not assumed here. Only actions an **API key** may
reach are served — audience and policy both have to admit a machine
caller — and the route is gated by `require_api_key` with one scope for
the tool surface, so a key that may read a report cannot also invoke an
admin action. Actions needing a browser (a CAPTCHA'd form) or a signed
link are not tools, because their proof is not one an API key carries.
The mapping is data, like ADR 0021's tool table: one row per action, so
"which tools exist" and "what a call does" cannot drift.

**5. Telephony and speech are shape only.** The port shape a later ADR
will decide: a `Telephony` inbound source for call and SMS webhooks (the
same verify-then-parse split as inbound mail) plus outbound
`send_sms`/`place_call`; and `SpeechToText`/`TextToSpeech` ports over the
existing `HttpClient`, so the vendor stays an adapter. Candidate vendors
for telephony/SMS: **Twilio, Telnyx, Vonage, Plivo**; for speech:
**Deepgram, AssemblyAI, OpenAI Whisper/TTS, ElevenLabs, Cloudflare
Workers AI**. No trait, no adapter and no crate exists for either yet.

## Rejected

**A `Port::InboundMail` variant.** The tracker precedent already
answered this for status webhooks and this is the same question: an
inbound delivery arrives at a route, verified with a per-endpoint
secret, and a module never reaches it through `module.ports()`. A port
variant would make one trait's absence a composition error for a service
that is a route — and cost `Port::ALL`, `Ports`, both runtimes and every
bundle the churn ADR 0025 warns about.

**Fetching the body inside `parse`.** Resend's webhook is metadata only,
so `parse` *could* call the Received-emails API and return a whole
message. It must not: `parse` is pure, an HTTP call inside it makes a
vendor outage look like a malformed delivery, and whether to fetch (and
with which key) is the caller's policy. `Ok(None)`/`None` fields say
what the delivery carried and nothing more.

**An HMAC scheme invented for Postmark.** Postmark's inbound webhook
signs with no HMAC — a shared token over HTTPS. Modelling it as a
signature would claim a guarantee the vendor does not give; the token
path (`SharedTokenScheme`) and the `Inbox` cover it honestly when that
adapter lands.

## Consequences

- `cratefield-core` gains `ports/inbound_mail.rs`, re-exported like its
  siblings; no `Port` variant, so `Harness::build`, `Port::ALL` and
  `Ports` are untouched and `HARNESS_API` stays 1.
- `cratefield-adapter-resend` gains `ResendInbound` (Svix verification,
  `RESEND_WEBHOOK_SECRET`), and `time` becomes a runtime dependency for
  the RFC 3339 `created_at`.
- Cloudflare Email Workers needs a MIME parser and a Worker `email()`
  entrypoint; Postmark needs the token scheme. Both are follow-ups, and
  neither blocks the Resend path.
- The runtime MCP route is a follow-up: it needs the Streamable HTTP
  transport, a scope for the tool surface, and the action-to-tool table
  in `cratefield-core`.
- Telephony and speech ship nothing; the vendor list is a starting point
  for the ADR that decides them.

## References

- Issue #563; issue #625 (tracker's inbound `StatusWebhook`, the shape
  this mirrors); ADR 0002 (ports and adapters), ADR 0019 (measurement
  before machinery), ADR 0021 (the MCP server is a thin wrapper).
- `crates/core/src/ports/inbound_mail.rs`,
  `crates/core/src/ports/tracker.rs`,
  `crates/core/src/webhook_signature.rs`,
  `crates/core/src/idempotency.rs`, `crates/core/src/surface.rs`,
  `crates/core/src/api_key.rs`, `crates/adapter-resend/src/inbound.rs`,
  `crates/mcp/`.
- Resend webhooks: `email.received` payload
  (https://resend.com/docs/webhooks/emails/received) and verification
  (https://resend.com/docs/dashboard/webhooks/verify-webhooks-requests);
  received-email content
  (https://resend.com/docs/dashboard/receiving/get-email-content).
- MCP Streamable HTTP transport:
  https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
