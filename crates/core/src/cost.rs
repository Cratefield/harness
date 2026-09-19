//! What routing costs (issue #457): per-adapter prices, the cost of one
//! call, and the ledger that totals them.
//!
//! **Money is an integer. Never `f64`.** [`Price`] stores **pico-USD per
//! token** (10^-12 USD), chosen so the numbers a vendor publishes map 1:1:
//! a price of `$X.YZ per million tokens` written in micro-USD is
//! numerically the same integer as pico-USD per token, so
//! [`Price::per_million_tokens`] takes the published figures directly.
//! [`Cost`] is pico-USD with saturating arithmetic — a call that
//! overflows a `u64` of pico-USD (about $18.4 million) saturates instead
//! of wrapping into a credit, and no single call comes near that. The
//! ledger's totals are deliberately wider: [`LedgerTotals::pico_usd`] is
//! a `u128`, because a total is a running sum over a ledger's whole life
//! and a `u64` of pico-USD would saturate it at that same $18.4 million.
//! A `u128` of pico-USD saturates near $3.4 × 10^26, which no ledger
//! reaches.
//!
//! **An adapter with no price on the sheet is unknown, not free.**
//! [`PriceSheet::cost_of`] answers [`Option::None`] for it, never
//! `Some(Cost::ZERO)`. The distinction is load-bearing: an unpriced call
//! is a call whose cost nobody wrote down, and a cheap-vs-expensive
//! argument built on a silently-zero cost is exactly the mistake this
//! module exists to prevent. Totals therefore count unpriced calls
//! separately ([`LedgerTotals::unpriced_calls`]) — answered calls the
//! sheet could not price, a wiring gap — and count the calls an adapter
//! **errored** on separately again ([`LedgerTotals::failed_calls`]),
//! because a failure is not a missing price and must not be mistaken
//! for one.
//!
//! The ledger contract ([`CostLedger`]) is deliberately **sync and
//! infallible**: recording what a decision cost must not be able to fail
//! a classification or add a network hop. A durable sink buffers in
//! memory and flushes on its own schedule, and its failures are its own.
//! [`InMemoryLedger`] is process-local — an isolate in a Worker — which
//! is fine for a measurement run and is not a billing system.

use std::collections::BTreeMap;
use std::fmt;

use crate::classifier::{AdapterId, QuestionKind};

/// Pico-USD in one USD: the unit of [`Cost`] and of both sides of
/// [`Price`].
const PICO_PER_USD: u64 = 1_000_000_000_000;

/// What one token costs on one adapter, in pico-USD, per side.
///
/// The fields are public and plain on purpose: a venture pastes the two
/// numbers off its vendor's pricing page (through
/// [`Price::per_million_tokens`]) and pricing updates are config, not
/// code. Prices go stale silently — an unpriced adapter and a
/// years-old price are both "the sheet says" — so the sheet is wired
/// where the adapters are, in one reviewable place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Price {
    pub input_pico_usd_per_token: u64,
    pub output_pico_usd_per_token: u64,
}

impl Price {
    /// A price of zero on both sides. This is a **known** free — a
    /// deliberate wiring choice such as a self-hosted model — which is
    /// not the same thing as an adapter missing from the sheet: see
    /// [`PriceSheet::cost_of`] for that distinction.
    pub const FREE: Price = Price {
        input_pico_usd_per_token: 0,
        output_pico_usd_per_token: 0,
    };

    /// Prices a vendor publishes. `$3.00 per million input tokens` is
    /// `per_million_tokens(3_000_000, ..)`: a `$X.YZ per million tokens`
    /// figure written in micro-USD is numerically the same integer as
    /// pico-USD per token, so the published numbers go in unchanged.
    #[must_use]
    pub const fn per_million_tokens(input_micro_usd: u64, output_micro_usd: u64) -> Price {
        Price {
            input_pico_usd_per_token: input_micro_usd,
            output_pico_usd_per_token: output_micro_usd,
        }
    }

    /// The cost of one call, saturating rather than wrapping: an
    /// astronomical token count is a bug to surface, not a credit to book.
    #[must_use]
    pub const fn cost(&self, input_tokens: u64, output_tokens: u64) -> Cost {
        Cost(
            input_tokens
                .saturating_mul(self.input_pico_usd_per_token)
                .saturating_add(output_tokens.saturating_mul(self.output_pico_usd_per_token)),
        )
    }
}

/// The pico-USD cost of **one call**.
///
/// Money is an integer: `f64` cannot add a million small calls and stay
/// honest about the sum. Saturating arithmetic, never wrapping.
///
/// The `u64` is per call on purpose. It saturates near **$18.4
/// million** of pico-USD, which no single classification spends; the
/// lifetime total of many calls is [`LedgerTotals::pico_usd`]'s job,
/// and that one is a `u128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Cost(u64);

impl Cost {
    /// The zero cost — what a known-free adapter spends.
    pub const ZERO: Cost = Cost(0);

    /// Wraps a raw pico-USD amount, as a total already summed elsewhere.
    #[must_use]
    pub const fn from_pico_usd(pico_usd: u64) -> Cost {
        Cost(pico_usd)
    }

    /// The raw amount in pico-USD, for totalling without rounding.
    #[must_use]
    pub const fn pico_usd(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Cost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Twelve decimals, because pico-USD is the unit: fewer digits
        // would round a small call to `$0.00` and lie about it.
        write!(
            f,
            "${}.{:012}",
            self.0 / PICO_PER_USD,
            self.0 % PICO_PER_USD
        )
    }
}

/// What each adapter costs, wired once where the adapters are wired.
///
/// A sheet with no entry for an adapter is the normal state of a new
/// adapter, not an error; the point of [`PriceSheet::cost_of`] answering
/// `None` is that the gap is visible where the money is totalled, not
/// papered over with zero at the pricing layer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PriceSheet(BTreeMap<AdapterId, Price>);

impl PriceSheet {
    /// An empty sheet: every adapter is unpriced until `.with(..)` says
    /// otherwise.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prices `adapter`, or replaces the price it had.
    #[must_use]
    pub fn with(mut self, adapter: AdapterId, price: Price) -> Self {
        self.0.insert(adapter, price);
        self
    }

    /// The price wired for `adapter`, if it has one.
    #[must_use]
    pub fn get(&self, adapter: &AdapterId) -> Option<Price> {
        self.0.get(adapter).copied()
    }

    /// What one call to `adapter` costs.
    ///
    /// [`Option::None`] when the adapter has no price on the sheet —
    /// **unknown, not free**. `Some(Cost::ZERO)` would silently win a
    /// cheap-vs-expensive argument that was never measured; `None` forces
    /// the caller (and the ledger's `unpriced_calls` count) to admit the
    /// price was missing.
    #[must_use]
    pub fn cost_of(
        &self,
        adapter: &AdapterId,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Option<Cost> {
        self.get(adapter)
            .map(|price| price.cost(input_tokens, output_tokens))
    }
}

/// Why a recorded call happened at all: which side of the routing
/// decision it was on.
///
/// [`CallRole::Discarded`] exists so the ledger can answer "what did
/// routing cost me over always-cheap" — an escalation pays twice, once
/// for the answer that was thrown away and once for the one served, and
/// that has to be visible or the cheap route looks free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallRole {
    /// Its answer went to the caller — or, when the call failed, its
    /// error did, because a served adapter's error reaches the caller
    /// unchanged. Either way this row names the adapter whose output
    /// the caller was left holding.
    Served,
    /// Asked to compare, never served: a live shadow call beside the
    /// answer that was served, or either side of an offline measurement
    /// run (`measure_agreement` asks both adapters precisely in order to
    /// compare them, and neither answer reaches a caller — it reaches
    /// the report).
    Shadow,
    /// Asked because the router planned to serve it, then thrown away:
    /// either the answer came back and was discarded for clearing no
    /// threshold, or the call itself failed and there was never an
    /// answer to throw away. Either way this row is the escalation's
    /// first half, so routing's double payment stays visible.
    Discarded,
}

/// How a recorded call ended. Failed calls are still recorded: a failed
/// call can still cost money, and a cheap adapter that fails often is not
/// cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallOutcome {
    /// The adapter answered.
    Ok,
    /// The adapter errored; whatever the call cost is still spent.
    Failed,
}

/// One classifier call, priced and role-tagged, as the ledger receives
/// it.
///
/// `#[non_exhaustive]`: records are produced by core's routers, and what
/// a record has to carry should grow without breaking the ventures that
/// read the totals. `cost` is [`Option::None`] when the adapter had no
/// price on the sheet — the call still happened, the money is just not
/// known.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallRecord {
    pub adapter: AdapterId,
    pub kind: QuestionKind,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost: Option<Cost>,
    pub role: CallRole,
    pub outcome: CallOutcome,
}

/// Sinks what routing decisions cost.
///
/// Deliberately **sync and infallible**: recording what a decision cost
/// must not be able to fail a classification or add a network hop. A
/// durable implementation buffers locally and flushes on its own
/// schedule; its delivery failures are its own to retry, not the
/// caller's.
pub trait CostLedger: Send + Sync {
    /// Records one call. Must not block on I/O or fail.
    fn record(&self, record: CallRecord);
}

/// The totals for one adapter — or one role — over a set of records.
///
/// `pico_usd` sums the **known** costs only; `unpriced_calls` counts
/// the answered calls whose price was missing, so a total is never
/// mistaken for complete; `failed_calls` counts the calls the adapter
/// errored on, because a cheap adapter that fails often is not cheap.
/// A totals row with `unpriced_calls > 0` is a wiring gap to fix, not a
/// cheap adapter to promote — while `failed_calls > 0` is an adapter
/// behaving badly, which is a different diagnosis with a different fix,
/// and conflating the two would send whoever reads the totals hunting
/// the sheet when the adapter is what failed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LedgerTotals {
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Sum of known costs, in pico-USD; excludes unpriced calls. A
    /// `u128`, wider than the per-call [`Cost`], on purpose: a total is
    /// a running sum over the ledger's whole life, and it must not
    /// saturate where a single call would not — a `u64` of pico-USD
    /// tops out near $18.4 million, a `u128` near $3.4 × 10^26.
    pub pico_usd: u128,
    /// Answered calls with no price on the sheet — the sheet could not
    /// price them. Zero is the only healthy value: this is a wiring gap
    /// to fix, not a cheap adapter to promote. A call the adapter
    /// errored on is missing a cost for a different reason, and is
    /// counted in [`Self::failed_calls`] instead.
    pub unpriced_calls: u64,
    /// Calls the adapter errored on, priced or not. A failed call can
    /// still cost money, and a cheap adapter that fails often is not
    /// cheap; this count is where that shows. The routers record a
    /// failure with no cost (the error carries no token counts to
    /// price), so counting failures here — not in `unpriced_calls` — is
    /// what keeps the wiring-gap diagnostic quiet on a correctly wired
    /// sheet.
    pub failed_calls: u64,
}

impl LedgerTotals {
    /// Folds one record in.
    fn accumulate(&mut self, record: &CallRecord) {
        self.calls = self.calls.saturating_add(1);
        self.input_tokens = self.input_tokens.saturating_add(record.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(record.output_tokens);
        if record.outcome == CallOutcome::Failed {
            self.failed_calls = self.failed_calls.saturating_add(1);
        }
        match record.cost {
            Some(cost) => {
                self.pico_usd = self.pico_usd.saturating_add(u128::from(cost.pico_usd()));
            }
            // Unpriced **and answered** is the wiring gap the count
            // exists for. A failed call carries no token counts to
            // price — the error carries none — so its missing cost is
            // the failure, not a missing price, and it is already
            // counted in `failed_calls`.
            None if record.outcome == CallOutcome::Ok => {
                self.unpriced_calls = self.unpriced_calls.saturating_add(1);
            }
            None => {}
        }
    }
}

/// A [`CostLedger`] that keeps the records in memory, in order, and can
/// total them.
///
/// Process-local by design — one isolate's view in a Worker, gone when it
/// is recycled — which is exactly right for a measurement run and a
/// report, and is not a billing system. A venture that needs the totals
/// to survive implements [`CostLedger`] over its own durable sink; the
/// contract stays sync and infallible, so the sink buffers and flushes on
/// its own.
#[derive(Debug, Default)]
pub struct InMemoryLedger {
    /// The records, oldest first. A `std::sync::Mutex` for interior
    /// mutability — the ledger is handed to a router as an
    /// explicitly-wired `Arc<dyn CostLedger>`, not ambient request state
    /// (ADR 0007), so the scoped allow follows the policy in the
    /// workspace clippy.toml.
    #[allow(clippy::disallowed_types)]
    records: std::sync::Mutex<Vec<CallRecord>>,
}

impl InMemoryLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Locks the record list, recovering from a poison rather than
    /// panicking: records are plain data appended under a short lock, so
    /// a poison would mean a panic mid-append — and throwing away every
    /// record recorded so far because of it would be the dishonest
    /// choice for a ledger.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<CallRecord>> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every record so far, oldest first — the raw material for a report
    /// the totals alone cannot write.
    #[must_use]
    pub fn records(&self) -> Vec<CallRecord> {
        self.lock().clone()
    }

    /// Totals per [`AdapterId`], the key prices and evidence are keyed by
    /// too.
    #[must_use]
    pub fn totals(&self) -> BTreeMap<AdapterId, LedgerTotals> {
        let mut totals: BTreeMap<AdapterId, LedgerTotals> = BTreeMap::new();
        for record in self.lock().iter() {
            totals
                .entry(record.adapter.clone())
                .or_default()
                .accumulate(record);
        }
        totals
    }

    /// The same totals per [`CallRole`], so "what did routing cost me
    /// over always-cheap" is one lookup: the `Discarded` row is what the
    /// escalation paid for nothing.
    #[must_use]
    pub fn role_totals(&self) -> BTreeMap<CallRole, LedgerTotals> {
        let mut totals: BTreeMap<CallRole, LedgerTotals> = BTreeMap::new();
        for record in self.lock().iter() {
            totals.entry(record.role).or_default().accumulate(record);
        }
        totals
    }
}

impl CostLedger for InMemoryLedger {
    fn record(&self, record: CallRecord) {
        self.lock().push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREE_DOLLARS_IN_PICO: u64 = 3_000_000_000_000;

    // -----------------------------------------------------------------
    // Price and Cost

    #[test]
    fn a_million_tokens_at_three_dollars_per_million_costs_exactly_three_dollars() {
        let price = Price::per_million_tokens(3_000_000, 15_000_000);
        let input_cost = price.cost(1_000_000, 0);
        assert_eq!(
            input_cost.pico_usd(),
            THREE_DOLLARS_IN_PICO,
            "the published micro-USD figure maps 1:1 onto pico-USD per token"
        );
        assert_eq!(
            input_cost.to_string(),
            "$3.000000000000",
            "the display is exactly the dollars spent"
        );
        let output_cost = price.cost(0, 1_000_000);
        assert_eq!(output_cost.pico_usd(), 15_000_000_000_000);
        // Both sides at once, and the composition is the sum.
        let both = price.cost(1_000_000, 1_000_000);
        assert_eq!(both.pico_usd(), 18_000_000_000_000);
    }

    #[test]
    fn cost_display_never_lies_about_small_amounts() {
        assert_eq!(
            Cost::from_pico_usd(3_000_000).to_string(),
            "$0.000003000000",
            "a small call is shown for what it is"
        );
        assert_eq!(
            Cost::from_pico_usd(1).to_string(),
            "$0.000000000001",
            "a single pico-USD must not round away to zero"
        );
        assert_eq!(Cost::ZERO.to_string(), "$0.000000000000");
    }

    #[test]
    fn a_cost_saturates_instead_of_wrapping() {
        let price = Price::per_million_tokens(u64::MAX, u64::MAX);
        let cost = price.cost(u64::MAX, u64::MAX);
        assert_eq!(
            cost.pico_usd(),
            u64::MAX,
            "an astronomical bill saturates, it never becomes a credit"
        );
    }

    // -----------------------------------------------------------------
    // PriceSheet

    #[test]
    fn an_adapter_with_no_price_on_the_sheet_is_unknown_not_free() {
        let cheap = AdapterId::new("cheap");
        let mystery = AdapterId::new("mystery");
        let sheet = PriceSheet::new().with(
            cheap.clone(),
            Price::per_million_tokens(1_000_000, 2_000_000),
        );
        assert_eq!(sheet.get(&mystery), None, "not wired yet, not zero");
        assert_eq!(
            sheet.cost_of(&mystery, 1_000, 1_000),
            None,
            "an unpriced call is a call whose cost nobody wrote down"
        );
        assert_eq!(
            sheet.cost_of(&cheap, 1_000_000, 0),
            Some(Cost::from_pico_usd(1_000_000_000_000)),
            "the priced adapter next to it answers with a real cost"
        );
    }

    #[test]
    fn a_known_free_adapter_is_priced_at_zero_which_is_not_unpriced() {
        let free = AdapterId::new("self-hosted");
        let sheet = PriceSheet::new().with(free.clone(), Price::FREE);
        assert_eq!(
            sheet.cost_of(&free, 10_000, 1_000),
            Some(Cost::ZERO),
            "a deliberate zero, distinguishable from a missing price"
        );
    }

    #[test]
    fn the_price_sheet_prices_a_call_and_replaces_a_stale_price() {
        let cheap = AdapterId::new("cheap");
        let sheet = PriceSheet::new()
            .with(
                cheap.clone(),
                Price::per_million_tokens(1_000_000, 2_000_000),
            )
            .with(
                cheap.clone(),
                Price::per_million_tokens(2_000_000, 4_000_000),
            );
        let cost = sheet
            .cost_of(&cheap, 1_000_000, 500_000)
            .expect("the adapter is priced");
        assert_eq!(
            cost.pico_usd(),
            4_000_000_000_000,
            "the newest price wins, so repricing is wiring not code"
        );
    }

    // -----------------------------------------------------------------
    // InMemoryLedger

    fn record(
        adapter: &AdapterId,
        input_tokens: u64,
        output_tokens: u64,
        cost: Option<Cost>,
        role: CallRole,
        outcome: CallOutcome,
    ) -> CallRecord {
        CallRecord {
            adapter: adapter.clone(),
            kind: QuestionKind::new("email_intent"),
            input_tokens,
            output_tokens,
            cost,
            role,
            outcome,
        }
    }

    #[test]
    fn totals_are_kept_per_adapter_and_unpriced_calls_are_counted_separately() {
        let cheap = AdapterId::new("cheap");
        let expensive = AdapterId::new("expensive");
        let mystery = AdapterId::new("mystery");
        let price = Price::per_million_tokens(1_000_000, 2_000_000);
        let ledger = InMemoryLedger::new();
        ledger.record(record(
            &cheap,
            1_000_000,
            0,
            Some(price.cost(1_000_000, 0)),
            CallRole::Served,
            CallOutcome::Ok,
        ));
        ledger.record(record(
            &cheap,
            500_000,
            0,
            Some(price.cost(500_000, 0)),
            CallRole::Served,
            CallOutcome::Ok,
        ));
        ledger.record(record(
            &expensive,
            1_000_000,
            1_000,
            Some(Price::per_million_tokens(3_000_000, 0).cost(1_000_000, 1_000)),
            CallRole::Served,
            CallOutcome::Ok,
        ));
        ledger.record(record(
            &mystery,
            1_000,
            1_000,
            None,
            CallRole::Shadow,
            CallOutcome::Ok,
        ));

        let totals = ledger.totals();
        assert_eq!(totals.len(), 3, "one row per adapter");
        let cheap_totals = &totals[&cheap];
        assert_eq!(cheap_totals.calls, 2);
        assert_eq!(
            cheap_totals.pico_usd, 1_500_000_000_000,
            "the two calls' known costs sum exactly, in integers"
        );
        assert_eq!(cheap_totals.unpriced_calls, 0);
        assert_eq!(cheap_totals.input_tokens, 1_500_000);
        let mystery_totals = &totals[&mystery];
        assert_eq!(
            mystery_totals.pico_usd, 0,
            "nothing is known, so nothing is summed"
        );
        assert_eq!(
            mystery_totals.unpriced_calls, 1,
            "and the gap is counted, not folded into a zero"
        );
        assert_eq!(mystery_totals.calls, 1, "the call still happened");
    }

    #[test]
    fn a_zero_cost_is_known_so_it_does_not_count_as_unpriced() {
        let free = AdapterId::new("self-hosted");
        let ledger = InMemoryLedger::new();
        ledger.record(record(
            &free,
            100,
            100,
            Some(Cost::ZERO),
            CallRole::Served,
            CallOutcome::Ok,
        ));
        let totals = &ledger.totals()[&free];
        assert_eq!(
            totals.unpriced_calls, 0,
            "Price::FREE is a price; only a missing sheet entry is unpriced"
        );
        assert_eq!(totals.pico_usd, 0);
    }

    #[test]
    fn a_failed_call_is_a_failure_not_an_unpriced_call() {
        let cheap = AdapterId::new("cheap");
        let ledger = InMemoryLedger::new();
        // How the routers record a failure: no token counts to price,
        // because the error carries none.
        ledger.record(record(
            &cheap,
            0,
            0,
            None,
            CallRole::Discarded,
            CallOutcome::Failed,
        ));
        ledger.record(record(
            &cheap,
            1_000,
            1_000,
            None,
            CallRole::Shadow,
            CallOutcome::Ok,
        ));
        let totals = &ledger.totals()[&cheap];
        assert_eq!(
            totals.failed_calls, 1,
            "the failure is counted as a failure"
        );
        assert_eq!(
            totals.unpriced_calls, 1,
            "and only the answered call without a price is a wiring gap — one \
             cheap-side failure must not fire the diagnostic on a correctly \
             wired sheet"
        );
        assert_eq!(totals.calls, 2, "both calls still happened");
    }

    #[test]
    fn totals_are_wider_than_one_call_so_a_ledger_does_not_saturate_where_a_call_would_not() {
        let cheap = AdapterId::new("cheap");
        let ledger = InMemoryLedger::new();
        let huge = Cost::from_pico_usd(u64::MAX);
        ledger.record(record(
            &cheap,
            0,
            0,
            Some(huge),
            CallRole::Served,
            CallOutcome::Ok,
        ));
        ledger.record(record(
            &cheap,
            0,
            0,
            Some(huge),
            CallRole::Served,
            CallOutcome::Ok,
        ));
        let totals = &ledger.totals()[&cheap];
        assert_eq!(
            totals.pico_usd,
            u128::from(u64::MAX) * 2,
            "two calls that would each saturate a `u64` total sum exactly in \
             `u128`: a long-running ledger does not top out at $18.4 million"
        );
    }

    #[test]
    fn totals_are_also_kept_per_role_so_an_escalations_waste_is_visible() {
        let cheap = AdapterId::new("cheap");
        let expensive = AdapterId::new("expensive");
        let price = Price::per_million_tokens(1_000_000, 2_000_000);
        let ledger = InMemoryLedger::new();
        // An escalation: the cheap answer was paid for and thrown away,
        // then the expensive one paid for and served.
        ledger.record(record(
            &cheap,
            1_000_000,
            0,
            Some(price.cost(1_000_000, 0)),
            CallRole::Discarded,
            CallOutcome::Ok,
        ));
        ledger.record(record(
            &expensive,
            1_000_000,
            1_000,
            Some(Price::per_million_tokens(3_000_000, 0).cost(1_000_000, 1_000)),
            CallRole::Served,
            CallOutcome::Ok,
        ));
        // A shadow call: asked to compare, never served, and failed —
        // which is still recorded, because it can still cost money.
        ledger.record(record(
            &cheap,
            1_000_000,
            0,
            Some(price.cost(1_000_000, 0)),
            CallRole::Shadow,
            CallOutcome::Failed,
        ));

        let roles = ledger.role_totals();
        assert_eq!(roles[&CallRole::Served].calls, 1);
        assert_eq!(
            roles[&CallRole::Discarded].calls,
            1,
            "the paid-for-and-thrown-away call is its own row"
        );
        assert_eq!(
            roles[&CallRole::Shadow].calls,
            1,
            "a shadow call that failed is still a call"
        );
        assert_eq!(
            roles[&CallRole::Shadow].pico_usd,
            1_000_000_000_000,
            "a failed call can still cost money"
        );
    }

    #[test]
    fn records_come_back_in_the_order_they_were_recorded() {
        let cheap = AdapterId::new("cheap");
        let expensive = AdapterId::new("expensive");
        let ledger = InMemoryLedger::new();
        ledger.record(record(
            &cheap,
            1,
            0,
            None,
            CallRole::Discarded,
            CallOutcome::Ok,
        ));
        ledger.record(record(
            &expensive,
            2,
            0,
            None,
            CallRole::Served,
            CallOutcome::Ok,
        ));
        let records = ledger.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].adapter, cheap, "oldest first");
        assert_eq!(records[1].adapter, expensive);
        assert_eq!(
            records[0].role,
            CallRole::Discarded,
            "the record is the call as it happened, not as it was summarised"
        );
    }
}
