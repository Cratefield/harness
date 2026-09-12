//! The control-plane billing model (issue #12's decision, issue #27's
//! screen): what a venture costs, which tier it is on, and the port a
//! Stripe adapter will one day answer.
//!
//! Three things live here and nowhere else:
//!
//! - **The pricing model as data** ([`PLATFORM_COSTS`], [`TIERS`]),
//!   transcribed from `docs/control-plane/PRICING.md`. The document is
//!   the decision; this crate is the same decision in a shape a screen
//!   can render. They cannot drift, because
//!   `cargo run -p cratefield-billing --example pricing-doc` regenerates
//!   the document's two data tables from this data and `--check` (CI)
//!   fails the run when they disagree — the same contract
//!   `errors-doc`, `compatibility-doc` and `push-env-doc` already hold
//!   with their registries.
//! - **The [`Tier`] a venture is on** — asked of the [`Billing`] port,
//!   never assumed. The port's only implementation today is [`Unwired`],
//!   which refuses, so every venture honestly reads as *free because no
//!   billing exists*, not free because a column said so. There is no
//!   tier column to keep in sync with reality for exactly that reason:
//!   a tier nobody can change through any real path is a convenient
//!   fiction, and this control plane does not record those.
//! - **The [`Billing`] port**: what Stripe will be asked to do — one
//!   subscription per venture, its current period, its invoices. Shaped
//!   after the provisioning `Deployer` seam: the live adapter holds
//!   the credential and is wired where the credential lives; everything
//!   else (the model, the records the model implies, the screen) is
//!   built and tested against the refusal.
//!
//! What deliberately does **not** live here: metering. A venture's
//! requests, storage and email cannot be counted while nothing reaches a
//! deployed venture to count them (#26), and a zero is not a measurement
//! — the screen says *not measured*, and this crate offers no API that
//! could be mistaken for one.
//!
//! Per-environment billing is out of scope on purpose: **one venture,
//! one bill.** Staging exists to rehearse changes, not to run up a tab,
//! and the day environments bill separately is a day this comment gets
//! rewritten with an ADR number beside it.
//!

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// The pricing model, as data
// ---------------------------------------------------------------------------

/// The date the Cloudflare numbers in [`PLATFORM_COSTS`] were verified
/// against Cloudflare's own published prices. `PRICING.md` carries the
/// same date and the same instruction: re-check before launch, because
/// it moves.
pub const PRICES_VERIFIED: &str = "2026-09-07";

/// One row of the platform cost table: what one venture consumes on
/// Cloudflare, what the free plan allows, what the paid plans include,
/// and what overage costs. Every string is transcribed from
/// `PRICING.md` byte for byte — the doc generator writes these rows back
/// into the document, so a disagreement fails CI rather than shipping.
pub struct CostLine {
    /// The resource being spent.
    pub resource: &'static str,
    /// What Cloudflare's free plan allows.
    pub free_plan_limit: &'static str,
    /// What the paid plans include, pooled across the account.
    pub paid_included: &'static str,
    /// What overage costs beyond the included amount.
    pub overage: &'static str,
}

/// What one venture consumes on Cloudflare, and what each part costs.
/// Hosted mode: every venture is one Worker + one D1 in Cratefield's own
/// account, so these are the per-unit costs the free tier is designed
/// around.
pub const PLATFORM_COSTS: &[CostLine] = &[
    CostLine {
        resource: "Workers requests",
        free_plan_limit: "100k/day",
        paid_included: "10M/mo ($5) · 20M/mo (Workers for Platforms)",
        overage: "$0.30 / million",
    },
    CostLine {
        resource: "Worker CPU",
        free_plan_limit: "10 ms/req",
        paid_included: "30M ms/mo ($5) · 60M ms/mo (WfP)",
        overage: "$0.02 / million ms",
    },
    CostLine {
        resource: "Worker scripts",
        free_plan_limit: "~100/account",
        paid_included: "~100 ($5) · **1,000 (WfP)**",
        overage: "$0.02 / script (WfP)",
    },
    CostLine {
        resource: "D1 rows read",
        free_plan_limit: "5M/day",
        paid_included: "25 **billion**/mo",
        overage: "$0.001 / million",
    },
    CostLine {
        resource: "D1 rows written",
        free_plan_limit: "100k/day",
        paid_included: "50 **million**/mo",
        overage: "$1.00 / million",
    },
    CostLine {
        resource: "D1 storage",
        free_plan_limit: "5 GB total, 500 MB/db",
        paid_included: "5 GB pooled, **10 GB/db** hard cap",
        overage: "$0.75 / GB-mo",
    },
    CostLine {
        resource: "D1 databases",
        free_plan_limit: "10",
        paid_included: "50,000 (raise on request)",
        overage: "—",
    },
    CostLine {
        resource: "Egress / bandwidth",
        free_plan_limit: "none",
        paid_included: "**none**",
        overage: "**none**",
    },
];

/// One row of the tier comparison: what the free tier and the paid tier
/// each include along one dimension.
pub struct TierLine {
    /// The dimension being compared (ventures, domain, requests, …).
    pub dimension: &'static str,
    /// What the free tier includes.
    pub free: &'static str,
    /// What the paid tier includes.
    pub paid: &'static str,
}

/// The header of the tier table's paid column. "Indicative" is the
/// document's own word: the paid tier's price is a design target, not a
/// price anybody has ever been charged.
pub const PAID_COLUMN: &str = "Paid (indicative, ~$19/mo)";

/// The two tiers the product plans to have. Competitive near-zero cost
/// to run, free forever, always on — the axis `PRICING.md` bets on.
pub const TIERS: &[TierLine] = &[
    TierLine {
        dimension: "Ventures",
        free: "1",
        paid: "several",
    },
    TierLine {
        dimension: "Domain",
        free: "`you.cratefield.app` subdomain",
        paid: "custom domain (Cloudflare for SaaS)",
    },
    TierLine {
        dimension: "Modules",
        free: "core + curated (signups, waitlist, CMS)",
        paid: "full catalog",
    },
    TierLine {
        dimension: "Requests",
        free: "~100k/mo, throttled not billed",
        paid: "high, then metered",
    },
    TierLine {
        dimension: "Database",
        free: "~100 MB D1, **always on**",
        paid: "up to 10 GB/db",
    },
    TierLine {
        dimension: "Email",
        free: "~100/mo shared domain",
        paid: "bring-your-own key, higher cap",
    },
    TierLine {
        dimension: "Captcha + rate limiting",
        free: "included (free on CF)",
        paid: "included",
    },
    TierLine {
        dimension: "Support / SLA",
        free: "community, none",
        paid: "as offered",
    },
];

/// What the free tier costs us to keep a quiet venture in, per
/// `PRICING.md`'s arithmetic: a free venture sits inside the pooled
/// allotments, so its only real marginal cost is the per-script fee —
/// and Workers and D1 scale to zero, which is why the free tier can
/// stay **always on** instead of pausing when idle.
///
/// Unlike the two tables, this figure lives in the document's
/// hand-written arithmetic rather than in a generated block, so the
/// generator will not rewrite it. [`marginal_cost_appears_in`] is the
/// coupling instead: the constant, without its `≈`, must appear
/// verbatim in the document, and `pricing-doc --check` fails the run
/// when it does not — edit both together, or neither.
pub const FREE_VENTURE_MARGINAL_COST: &str = "≈ $0.02/month";

// ---------------------------------------------------------------------------
// The tier
// ---------------------------------------------------------------------------

/// Which tier a venture is on. Asked of the [`Billing`] port; with
/// [`Unwired`] wired the honest answer is [`Tier::Free`] *because no
/// billing exists*, and the screen says so rather than reading a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The always-on, throttled-at-the-ceiling tier. A throttle, never a
    /// pause: exceeding a free-tier limit may slow a venture down and may
    /// never suspend, archive or stop it.
    Free,
    /// The metered tier. Indicative price only — nobody has ever been
    /// charged, and nothing in this crate can charge anybody.
    Paid,
}

impl Tier {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Free => "free",
            Tier::Paid => "paid",
        }
    }
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// What a venture's subscription looks like to the control plane: the
/// tier, and the period the subscription currently covers. Stripe's own
/// shape, reduced to the fields a screen renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// The venture the subscription belongs to. One venture, one
    /// subscription: environments do not bill (#31's screen says the
    /// same).
    pub venture_id: String,
    pub tier: Tier,
    /// ISO-8601 timestamps of the current billing period's start and
    /// end.
    pub period: Period,
    /// Stripe's subscription status (`active`, `past_due`, …), verbatim.
    pub status: String,
}

/// A billing period, as ISO-8601 boundary timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Period {
    pub starts: String,
    pub ends: String,
}

/// One invoice. Total in minor units (cents) with its currency, so no
/// floating point ever holds money.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// The Stripe invoice id (`in_…`).
    pub id: String,
    pub venture_id: String,
    pub period: Period,
    /// The invoice total, in minor units (cents).
    pub total: u64,
    /// Lower-case ISO currency code (`usd`).
    pub currency: String,
    /// Stripe's invoice status (`paid`, `open`, `void`, …), verbatim.
    pub status: String,
}

/// Why a billing call failed. Carries a message that is safe to record
/// and render: it must never contain a credential, exactly like a
/// `DeployError`.
///

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingError {
    pub message: String,
}

impl BillingError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BillingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BillingError {}

/// What Stripe will be asked to do, behind a port. One subscription per
/// venture (with its current period) and the venture's invoices — the
/// two reads the billing screen needs, and the shape a live adapter
/// fills from Stripe's API. Everything that would *write* (creating the
/// subscription, charging the card) is deliberately absent: charging is
/// a checkout flow the customer drives in Stripe's own pages, and the
/// control plane records what Stripe reports, never a charge it thinks
/// happened.
///
/// The port is async because a real adapter is; see the provisioning
/// `Deployer` for the same choice. The venture-side Stripe adapter
/// (`cratefield-adapter-stripe`, the harness `Payments` port) is a
/// different seam: that one serves a venture's own customers inside a
/// venture. This one bills the venture's owner for the venture.
#[allow(async_fn_in_trait)]
pub trait Billing {
    /// The venture's subscription: which tier it is on and the current
    /// period.
    ///
    /// # Errors
    ///
    /// [`BillingError`] when no adapter is wired or Stripe could not be
    /// reached. A refusal is a fact to render, never a default tier to
    /// fall back to.
    async fn subscription_for(&self, venture_id: &str) -> Result<Subscription, BillingError>;

    /// The venture's invoices, newest first.
    ///
    /// # Errors
    ///
    /// [`BillingError`], same contract as [`Billing::subscription_for`].
    async fn invoices_for(&self, venture_id: &str) -> Result<Vec<Invoice>, BillingError>;
}

/// The billing adapter the control plane has today: none.
///
/// Same contract as the provisioning `Unwired`: run the question for
/// real and let it stop where it stops. The refusal is returned to the
/// screen, which renders it — "no billing is wired" — rather than
/// falling back to a tier or an empty invoice list that would read as
/// "free, and up to date". Nobody has ever been charged, and the screen
/// says that in plain text instead of implying otherwise.
pub struct Unwired;

impl Unwired {
    /// The one message, so every refusal reads the same whichever call
    /// happens to be first.
    fn refuse<T>(what: &str) -> Result<T, BillingError> {
        Err(BillingError::new(format!(
            "no billing is wired: {what} needs an adapter that talks to Stripe, and the \
             control plane has none yet. Nobody has ever been charged, and nothing was \
             changed."
        )))
    }
}

// Every method answers without awaiting anything, which is the whole
// point: there is nothing to talk to. The port is async because a real
// adapter is.
#[allow(clippy::unused_async_trait_impl)]
impl Billing for Unwired {
    async fn subscription_for(&self, venture_id: &str) -> Result<Subscription, BillingError> {
        let _ = venture_id;
        Self::refuse("reading the venture's subscription")
    }

    async fn invoices_for(&self, venture_id: &str) -> Result<Vec<Invoice>, BillingError> {
        let _ = venture_id;
        Self::refuse("listing the venture's invoices")
    }
}

// ---------------------------------------------------------------------------
// The document, generated from the data
// ---------------------------------------------------------------------------

/// The marker pair that brackets the platform cost table in
/// `docs/control-plane/PRICING.md`. Everything between them is
/// generated; everything outside them is prose a person wrote.
pub const PLATFORM_MARKERS: (&str, &str) = (
    "<!-- pricing-doc: platform-costs begin (generated; edit \
     crates/control-plane-billing and run the pricing-doc example) -->",
    "<!-- pricing-doc: platform-costs end -->",
);

/// The marker pair that brackets the tier table in
/// `docs/control-plane/PRICING.md`.
pub const TIER_MARKERS: (&str, &str) = (
    "<!-- pricing-doc: tiers begin (generated; edit \
     crates/control-plane-billing and run the pricing-doc example) -->",
    "<!-- pricing-doc: tiers end -->",
);

/// The platform cost table as markdown, byte-identical to the table
/// `PRICING.md` shipped before the generator existed — so wiring the
/// generator changed the document's maintenance, not its content.
#[must_use]
pub fn platform_costs_markdown() -> String {
    let mut lines = vec![
        "| Resource | Free-plan limit | Paid included (pooled across the account) | Overage |"
            .to_owned(),
        "| :--- | :--- | :--- | :--- |".to_owned(),
    ];
    for line in PLATFORM_COSTS {
        lines.push(format!(
            "| {} | {} | {} | {} |",
            line.resource, line.free_plan_limit, line.paid_included, line.overage
        ));
    }
    lines.join("\n")
}

/// The tier table as markdown, same contract as
/// [`platform_costs_markdown`].
#[must_use]
pub fn tier_table_markdown() -> String {
    let mut lines = vec![
        format!("| | Free | {PAID_COLUMN} |"),
        "| :--- | :--- | :--- |".to_owned(),
    ];
    for line in TIERS {
        lines.push(format!(
            "| {} | {} | {} |",
            line.dimension, line.free, line.paid
        ));
    }
    lines.join("\n")
}

/// Why regenerating the document failed: a marker pair is missing, so
/// there is no defined place for the generated tables to land. Names
/// the missing pair rather than guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingMarkers(&'static str);

impl std::fmt::Display for MissingMarkers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "docs/control-plane/PRICING.md has no {} markers; add them around the \
             hand-written table, then run the pricing-doc example",
            self.0
        )
    }
}

impl std::error::Error for MissingMarkers {}

/// Whether `doc` still carries the free-venture marginal cost this
/// crate asserts. The figure is the document's hand-written arithmetic,
/// not a generated table, so the generator refuses to rewrite it and
/// this predicate is the drift check instead: the constant minus its
/// `≈` must appear verbatim. The `pricing-doc` example fails both of
/// its modes when it does not.
#[must_use]
pub fn marginal_cost_appears_in(doc: &str) -> bool {
    // `≈ ` and any surrounding space are presentation, not the figure:
    // the document writes "**$0.02/month WfP script fee**", so the
    // needle is the trimmed "$0.02/month".
    doc.contains(FREE_VENTURE_MARGINAL_COST.trim_start_matches('≈').trim())
}

/// Rewrites `doc` with both generated tables in place of whatever
/// currently sits between their markers. Everything outside the markers
/// is preserved byte for byte, so the prose stays a person's.
///
/// # Errors
///
/// [`MissingMarkers`] when either marker pair is absent — the generator
/// refuses to guess where a table belongs, the same rule the screen
/// applies to everything else it renders.
pub fn sync_pricing_doc(doc: &str) -> Result<String, MissingMarkers> {
    let doc = replace_section(
        doc,
        PLATFORM_MARKERS,
        &platform_costs_markdown(),
        "platform-costs",
    )?;
    replace_section(&doc, TIER_MARKERS, &tier_table_markdown(), "tiers")
}

fn replace_section(
    doc: &str,
    markers: (&str, &str),
    body: &str,
    name: &'static str,
) -> Result<String, MissingMarkers> {
    let Some(start) = doc.find(markers.0) else {
        return Err(MissingMarkers(name));
    };
    // The end marker must come after the begin marker; a document with
    // them the wrong way round is not a document to trust.
    let Some(end) = doc[start + markers.0.len()..].find(markers.1) else {
        return Err(MissingMarkers(name));
    };
    let end = start + markers.0.len() + end;
    let mut out = String::with_capacity(doc.len());
    out.push_str(&doc[..start]);
    out.push_str(markers.0);
    out.push('\n');
    out.push_str(body);
    out.push('\n');
    out.push_str(markers.1);
    out.push_str(&doc[end + markers.1.len()..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[pollster::test]
    async fn the_unwired_port_refuses_rather_than_answering() {
        let err = Unwired.subscription_for("v1").await.expect_err("refuses");
        assert!(err.message.contains("no billing is wired"), "{err}");
        // The refusal carries the fact the screen leans on: nobody has
        // ever been charged, and the call changed nothing.
        assert!(
            err.message.contains("Nobody has ever been charged"),
            "{err}"
        );
        assert!(err.message.contains("nothing was changed"), "{err}");

        let err = Unwired.invoices_for("v1").await.expect_err("refuses");
        assert!(err.message.contains("no billing is wired"), "{err}");
    }

    #[test]
    fn the_tier_table_renders_the_dimensions_the_document_decided() {
        let table = tier_table_markdown();
        // The dimensions are the product commitment; losing one to a
        // refactor would silently narrow the free tier's promise.
        for dimension in [
            "Ventures",
            "Domain",
            "Modules",
            "Requests",
            "Database",
            "Email",
            "Captcha + rate limiting",
            "Support / SLA",
        ] {
            assert!(table.contains(dimension), "{dimension} missing: {table}");
        }
        // The commitment this whole screen exists to keep visible.
        assert!(table.contains("throttled not billed"), "{table}");
        assert!(table.contains("**always on**"), "{table}");
    }

    #[test]
    fn the_platform_table_renders_every_resource_and_the_egress_edge() {
        let table = platform_costs_markdown();
        assert_eq!(PLATFORM_COSTS.len(), 8, "one row per resource");
        assert!(table.contains("Egress / bandwidth"), "{table}");
        // "—" is the doc's own spelling of "no such thing as an overage
        // here"; a refactor that turns it into "-" changes the document.
        assert!(table.contains("| — |"), "{table}");
        assert!(table.contains("**none** | **none**"), "{table}");
    }

    #[test]
    fn a_document_with_both_markers_syncs_without_touching_the_prose() {
        let doc = "Intro prose a person wrote.\n\
                   <!-- pricing-doc: platform-costs begin (generated; edit \
                   crates/control-plane-billing and run the pricing-doc example) -->\n\
                   | stale | table |\n\
                   <!-- pricing-doc: platform-costs end -->\n\
                   Middle prose.\n\
                   <!-- pricing-doc: tiers begin (generated; edit \
                   crates/control-plane-billing and run the pricing-doc example) -->\n\
                   | old | tiers |\n\
                   <!-- pricing-doc: tiers end -->\n\
                   Closing prose.\n";
        let synced = sync_pricing_doc(doc).expect("both markers present");
        assert!(
            synced.starts_with("Intro prose a person wrote.\n"),
            "{synced}"
        );
        assert!(synced.contains("Middle prose."), "{synced}");
        assert!(synced.ends_with("Closing prose.\n"), "{synced}");
        assert!(synced.contains("| Resource | Free-plan limit"), "{synced}");
        assert!(!synced.contains("| stale | table |"), "{synced}");
        assert!(!synced.contains("| old | tiers |"), "{synced}");
        // Idempotent: a second pass changes nothing, which is what
        // `--check` relies on to mean "no drift".
        assert_eq!(sync_pricing_doc(&synced).expect("still present"), synced);
    }

    #[test]
    fn the_marginal_cost_figure_is_coupled_to_the_documents_prose() {
        // The real document's shape: the figure sits mid-paragraph in
        // hand-written arithmetic ("the **$0.02/month WfP script fee**").
        let doc = "prose\nmarginal cost is the **$0.02/month WfP script fee** once past\n";
        assert!(marginal_cost_appears_in(doc));
        // A constant the document disagrees with — the exact drift the
        // check exists to catch, found in either direction.
        assert!(!marginal_cost_appears_in(
            "marginal cost is the **$0.99/month WfP script fee**"
        ));
        assert!(!marginal_cost_appears_in("no figure at all"));
    }

    #[test]
    fn a_document_missing_its_markers_is_refused_by_name() {
        let err = sync_pricing_doc("no markers at all").expect_err("refuses");
        assert!(err.to_string().contains("platform-costs"), "{err}");
        let half = "prose\n<!-- pricing-doc: platform-costs begin (generated; edit \
                    crates/control-plane-billing and run the pricing-doc example) -->\n\
                    but never closed\n";
        let err = sync_pricing_doc(half).expect_err("refuses");
        assert_eq!(err, MissingMarkers("platform-costs"));
    }
}
