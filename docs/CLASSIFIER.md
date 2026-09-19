# Classifier: a typed, calibrated decision

The `Classifier` port (issue #456), the sibling of `TextModel`. Where a text
model completes prose, a classifier answers "which of these is it, and how sure
are you" about a `state` — is this support note about billing or a bug, how
severe is it, is the writer angry. A module holds `Arc<dyn Classifier>` and
never learns who answered; which adapter stands behind the port is the venture's
wiring, decided once and invisible to the module.

## The three questions, asked as a set

A classifier is asked three kinds of thing, so the port has three
`Question` shapes:

- `Question::Choice` — pick one of a named set. The criteria map carries
  what each criterion means, because the provider only sees the words it is
  given; its keys are the labels the answer's probabilities are keyed by.
- `Question::Score` — place the state on an ordered scale. The levels are
  `(name, what that level means)`, in order.
- `Question::Noul` — yes or no, answered as `true` or `false`.

Questions are asked **as a set, not in a loop**. The provider evaluates every
question of one `ask` call against one `state` in parallel — the expensive part
of the call is carrying the state, not answering — so adding a question barely
changes the response time. A loop of one-question calls is possible but is the
wrong shape: it pays for the state once per question and serialises what the
provider would have run concurrently. `ask` therefore takes a
`BTreeMap<String, Question>` and hands back answers keyed the same way.

Adapters run `validate_questions` before they render a set, so a malformed one
lands as `ClassifierError::Rejected` and never as a panic: an empty set, a
blank id, blank instructions, a `Choice` with fewer than two criteria, a
`Score` with fewer than two levels.

## The adapters

| Adapter | How it reaches the model | Key it needs | Why you pick it |
|---|---|---|---|
| `cratefield-adapter-typesafe` | the operator's own TypeSafe account, over the `HttpClient` port | the operator's TypeSafe key | the default. Works on every runtime, keeps the vendor account and the bill with the operator |
| `cratefield-adapter-workers-ai` | the Cloudflare `env.AI` binding | none — the binding rides the account's Workers AI subscription | zero new credentials on a Workers deployment |
| `cratefield-adapter-classifier-llm` | the `TextModel` port already wired, structured output via `Prompt::json_schema` | none of its own — whatever the text model's tiers are wired to | no new vendor when a venture already has a `TextModel`; one more bill line instead of one more account |

Bring-your-own-key is the default and the way in: the venture constructs the
adapter with its key and passes it — `.classifier(..)` or `.classifier_arc(..)`
on either runtime, the same as `text_model`. The Workers AI binding is a
convenience for a venture already on Cloudflare, not the path the port was
shaped around; the port wires identically on both runtimes, and
`runtime-browser` does not carry it, following `TextModel`'s precedent.

## Confidence is not comparable across adapters

This is the property the port exists to make loud. A `0.8` from a
purpose-trained classifier and a `0.8` elicited from a general language model
are different numbers: calibration is a property of the family the numbers come
from, not a universal scale, and a threshold tuned against one family is wrong
against the other. `Calibration::{Classifier, LanguageModel}` names the two
families this repo recognises, and every adapter reports which one its numbers
are through `profile().calibration`.

A module that thresholds on `Answer::confidence` must say so in its own docs:
the threshold is **per-adapter**, and swapping the adapter re-tunes every
threshold downstream of it. Checking `profile()` at startup and refusing to run
against a calibration the threshold was not tuned for is a reasonable response;
comparing confidences across two adapters is not.

## State is truncated

Every adapter truncates `state` past its `max_state_chars` — only the adapter
knows its provider's budget, so only the adapter can enforce it.
`DEFAULT_MAX_STATE_CHARS` (96,000 chars, roughly 4 chars per token against the
32k-token window Workers AI documents) is what a conservative adapter reports.
Truncation is deterministic and on a char boundary — `ClassifierProfile::truncate`
is the shared helper, and the same state always trims to the same prefix — and
the adapter **logs when it drops anything**.

The log line is not decoration. A silently trimmed state is the worst failure
mode a classifier has: the question still gets answered, the answer still comes
back confident, and nothing in the types says the state was cut — a module
triaging support notes would act on the first 96,000 characters as if they were
the whole note. Confidence and truncation interact the wrong way, so the port's
contract is that the cut is always visible in the logs.

## Not in the port

No training and no feedback loop — the port answers questions, it does not
learn from the answers. No streaming — a decision is one request and one
answer, like `TextModel`'s completion. And no persistence: if the decision
matters later, the module writes it down.
