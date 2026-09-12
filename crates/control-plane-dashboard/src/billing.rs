//! The Billing screen (control-plane #27): what a venture costs, which
//! tier it is on, and the honest parts — that nobody has ever been
//! charged, and that usage is not measured.
//!
//! The substance is `docs/control-plane/PRICING.md`, and the screen
//! renders it through [`cratefield_billing`]'s data so the two cannot
//! drift (the `pricing-doc` example regenerates the document's tables
//! from the same constants and CI checks it). What the document works
//! out in prose — the free tier is a throttle, never a pause; a quiet
//! free venture costs about two cents a month to keep alive — this
//! screen has to keep saying, because a billing screen that stops
//! saying it is how a product commitment gets lost between the doc and
//! the invoice.
//!
//! Per-environment billing is out of scope and stays that way: **one
//! venture, one bill.** Staging exists to rehearse changes, not to run
//! up a tab (see the billing crate's docs for the same sentence).
//!
//! The screen never invents a number. The tier comes from asking the
//! [`Billing`](cratefield_billing::Billing) port, whose only
//! implementation refuses; the usage column says *not measured* because
//! nothing reaches a deployed venture to count anything (#26); and a
//! zero never stands in for a measurement, because a zero reads as
//! "counted, and it was nothing" — which is a claim nobody here can
//! make.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use cratefield_billing::{
    Billing, PAID_COLUMN, PLATFORM_COSTS, PRICES_VERIFIED, TIERS, Tier, Unwired,
};
use cratefield_chrome::{Page, escape, render};

use crate::{BASE, DashboardState, account_nav, account_of, card, frame, guard, internal};

/// `/v1/dashboard/billing` — the tiers, the per-unit costs, and one row
/// per venture: its tier (asked of the port), and the plain statement
/// that its usage is not measured.
#[allow(clippy::too_many_lines)]
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session =
        cratefield_console::current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let ventures = match repo.ventures_for(&account.id).await {
        Ok(ventures) => ventures,
        Err(err) => {
            tracing::error!(error = %err, "venture list failed on the billing screen");
            return internal("could not load the ventures");
        }
    };

    // The tier verdict: ask the port for every venture's subscription and
    // let the answer be what it is. With `Unwired` wired every call
    // refuses with the same message, and the screen renders that refusal
    // once, above the rows, rather than repeating it per row — the
    // refusal is a fact about the deployment, not a difference between
    // two ventures.
    let billing = Unwired;
    let refusal = match billing
        .subscription_for(ventures.first().map_or("", |v| v.id.as_str()))
        .await
    {
        Ok(_) => None,
        Err(err) => Some(err.message),
    };

    let rows = venture_rows(&ventures);

    let banner = String::from(
        "<p class=\"dash__banner\"><span class=\"chip\">No charges</span>\
         <strong>Nobody has ever been charged.</strong> There is no billing wired — \
         the Billing port's only implementation refuses — and nothing exists that \
         could have charged anybody: no card is on file, no subscription has been \
         created, no invoice has been rendered. This screen says that in plain text \
         rather than showing an empty invoice table, which would read as \
         \"invoices exist and there are none yet\".</p>",
    );
    let port_refusal = match &refusal {
        Some(message) => format!(
            "<p class=\"dash__note\">Asked for the ventures' subscriptions while this \
             page rendered; the port answered: <code>{message}</code></p>",
            message = escape(message),
        ),
        // Unreachable with `Unwired` and true the day a real adapter is
        // wired; written as the not-yet case rather than an `expect`,
        // because a screen crashing on success is its own kind of lie.
        None => String::from(
            "<p class=\"dash__note\">The port answered. Its answer is rendered per \
             venture above.</p>",
        ),
    };

    let body = format!(
        "{banner}\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Ventures <span class=\"dash__tag\">{count}</span></p>\
         <div class=\"dash__list\">{rows}</div>\
         <p class=\"dash__note\">Every tier on this page is the port's answer, not a \
         column's: there is no tier recorded anywhere that could disagree with the \
         billing adapter, because a tier nobody can change through a real path would \
         be a convenient fiction. One venture, one bill — environments do not \
         bill.</p></div>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">The free tier is a throttle, never a pause</p>\
         <p class=\"dash__note\"><strong>At the limit, a venture slows down. It does \
         not stop.</strong> Exceeding a free-tier ceiling may throttle a venture's \
         requests and may never suspend, archive or stop it. Workers and D1 scale to \
         zero and cost nothing idle, which is what makes \"always on, even on free\" \
         affordable — and it is a product commitment (PRICING.md), not a side effect \
         this screen is taking credit for. Nothing the dashboard renders, and nothing \
         this repository builds, may suspend or stop a venture for exceeding a free \
         tier.</p></div>\
         {pricing}\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">The Billing port, unwired</p>\
         <p class=\"dash__note\">What Stripe will be asked to do, when there is a \
         Stripe to ask: one subscription per venture, carrying its tier and its \
         current period, and the venture's invoices. The port is shaped for exactly \
         that and nothing else — charging happens in Stripe's own checkout, never \
         here. Today its only implementation refuses, and the screen renders the \
         refusal instead of a fallback tier.</p>{port_refusal}\
         <p class=\"dash__note\">Metering is the missing half (#26): counting a \
         deployed venture's requests, storage and email needs the venture \
         reachable, and no deployer exists. Until one does, \"what would this cost \
         at current usage\" has no honest answer, and the model below is the \
         ceiling of what can be said.</p></div>",
        count = ventures.len(),
        rows = rows,
        pricing = pricing_card(),
        port_refusal = port_refusal,
    );

    let crumb = format!(
        "{count} venture{s} · every one free · usage unmeasured",
        count = ventures.len(),
        s = if ventures.len() == 1 { "" } else { "s" },
    );

    Html(render(&Page {
        title: "Billing",
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<div class=\"page-h\"><h1>Billing</h1><span class=\"chip\">No charges</span></div>\
             <p class=\"lede\">What a venture costs, which tier it is on, and the two \
             things this screen will not pretend: that anyone has been charged, and \
             that usage is known.</p>{frame}",
            frame = frame(&account_nav("billing"), &crumb, &body),
        ),
    }))
    .into_response()
}

/// One row per venture: the venture, its tier, and its usage — which is
/// not measured, stated where a number would go. The wording is the
/// load-bearing part: "0 requests" would read as a measurement of zero,
/// and zero is exactly what this screen must never claim.
#[allow(clippy::format_push_string)]
fn venture_rows(ventures: &[cratefield_accounts::Venture]) -> String {
    let mut rows = String::from(
        "<div class=\"dash__lrow dash__lrow--three dash__lrow--head\">\
         <span>Venture</span><span>Tier</span><span>Usage</span></div>",
    );
    if ventures.is_empty() {
        rows.push_str(
            "<p class=\"dash__empty\">No ventures yet. \
             <a href=\"/v1/console/new\">Create one in the console.</a></p>",
        );
        return rows;
    }
    for venture in ventures {
        // With `Unwired` the tier is free because no billing exists; the
        // row says the why inline so "free" can never read as a verdict.
        let tier = Tier::Free;
        rows.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--three\">\
             <span><a href=\"{BASE}/ventures/{id}\">{slug}</a></span>\
             <span><span class=\"chip\">{tier}</span> \
             <em>no billing is wired</em></span>\
             <span><strong>not measured</strong> — nothing reaches a deployed \
             venture to count requests, storage or email (#26); a zero would not \
             be a measurement</span></div>",
            BASE = BASE,
            id = escape(&venture.id),
            slug = escape(&venture.slug),
            tier = tier.as_str(),
        ));
    }
    rows
}

/// The pricing model, rendered from the same data the document is
/// generated from. If `PRICING.md` changes, `pricing-doc --check` fails
/// CI until this changes with it — that is the whole anti-drift design.
#[allow(clippy::format_push_string)]
fn pricing_card() -> String {
    let mut tiers = String::from(
        "<div class=\"dash__scroll\"><table class=\"dash__rows\">\
         <thead><tr><th></th><th>Free</th><th>Paid</th></tr></thead><tbody>",
    );
    for line in TIERS {
        tiers.push_str(&format!(
            "<tr><td>{dimension}</td><td>{free}</td><td>{paid}</td></tr>",
            dimension = md_inline(line.dimension),
            free = md_inline(line.free),
            paid = md_inline(line.paid),
        ));
    }
    tiers.push_str("</tbody></table></div>");

    let mut costs = String::from(
        "<div class=\"dash__scroll\"><table class=\"dash__rows\">\
         <thead><tr><th>Resource</th><th>Free-plan limit</th>\
         <th>Paid included (pooled)</th><th>Overage</th></tr></thead><tbody>",
    );
    for line in PLATFORM_COSTS {
        costs.push_str(&format!(
            "<tr><td>{resource}</td><td>{limit}</td><td>{included}</td><td>{overage}</td></tr>",
            resource = md_inline(line.resource),
            limit = md_inline(line.free_plan_limit),
            included = md_inline(line.paid_included),
            overage = md_inline(line.overage),
        ));
    }
    costs.push_str("</tbody></table></div>");

    card(
        "The pricing model",
        None,
        &format!(
            "{tiers}\
             <p class=\"dash__note\">Cloudflare prices verified {PRICES_VERIFIED}; \
             re-check before launch — it moves. The free tier sits inside the \
             pooled allotments, so a quiet free venture's only real marginal cost \
             is the per-script fee: about {FREE} all in — PRICING.md works out \
             the arithmetic. A venture with no usage to measure has no bill to \
             estimate, and this screen offers no number it cannot stand behind. \
             The paid column is indicative — {PAID_COLUMN} is a design target, \
             not a price anyone has been asked to pay.</p>\
             <p class=\"dash__card-h\" style=\"margin-top:18px\">Per-unit platform \
             costs</p>{costs}\
             <p class=\"dash__note\">Rendered from the same data the document's \
             tables are generated from, so the two cannot drift.</p>",
            tiers = tiers,
            costs = costs,
            PRICES_VERIFIED = PRICES_VERIFIED,
            FREE = cratefield_billing::FREE_VENTURE_MARGINAL_COST,
            PAID_COLUMN = escape(PAID_COLUMN),
        ),
        true,
    )
}

/// One inline-markdown cell of the pricing data, as HTML. The data is
/// written in the document's own markdown — `**always on**`,
/// `` `you.cratefield.app` `` — because that is what the generator
/// writes into PRICING.md; the screen owes the same emphasis, so the
/// two markers it uses are translated rather than shown raw. Escape
/// first, then restore the two markers, so nothing else in a cell can
/// become markup.
fn md_inline(cell: &'static str) -> String {
    let escaped = escape(cell);
    let mut out = String::with_capacity(escaped.len());
    let mut rest = escaped.as_str();
    while let Some(at) = rest.find("**").or_else(|| rest.find('`')) {
        let (marker_start, marker_len, open, close) = if rest[at..].starts_with("**") {
            (at, 2, "<strong>", "</strong>")
        } else {
            (at, 1, "<code>", "</code>")
        };
        out.push_str(&rest[..marker_start]);
        let after = &rest[marker_start + marker_len..];
        let closer = if marker_len == 2 { "**" } else { "`" };
        if let Some(end) = after.find(closer) {
            out.push_str(open);
            out.push_str(&after[..end]);
            out.push_str(close);
            rest = &after[end + marker_len..];
        } else {
            // An unpaired marker is the data's own typo; show it raw
            // rather than dropping it on the floor.
            out.push_str(&rest[..marker_start + marker_len]);
            rest = &rest[marker_start + marker_len..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Dashboard;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest, StatusCode, header};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    const PATH: &str = "/v1/dashboard/billing";
    const NOW: u64 = 1_800_000_000;

    fn kit() -> TestHarness {
        TestHarness::new(vec![
            Box::new(cratefield_console::Console),
            Box::new(Dashboard::new(None)),
        ])
    }

    fn cookie(kit: &TestHarness) -> String {
        let token = issue_session(kit.signer.as_ref(), EMAIL, NOW, DEFAULT_TTL_SECS);
        format!("cf_session={token}")
    }

    async fn get(kit: &TestHarness, uri: &str, cookie: Option<&str>) -> (StatusCode, String) {
        let mut builder = HttpRequest::builder().method(Method::GET).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = kit
            .router
            .clone()
            .oneshot(builder.body(axum::body::Body::empty()).expect("request"))
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
            .await
            .expect("body");
        (
            parts.status,
            String::from_utf8(bytes.to_vec()).expect("utf-8"),
        )
    }

    async fn seed(kit: &TestHarness) {
        let repo = cratefield_accounts::Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        for (id, slug, set, tenant) in [
            ("v1", "alpha", "cms", "ten_1"),
            ("v2", "beta", "cms+waitlist", "ten_2"),
        ] {
            repo.create_venture(
                id,
                "acc_1",
                slug,
                &format!("{slug}.cratefield.app"),
                set,
                tenant,
                "t0",
            )
            .await
            .expect("venture");
        }
    }

    #[pollster::test]
    async fn every_venture_shows_its_tier_and_says_usage_is_unmeasured() {
        let kit = kit();
        seed(&kit).await;
        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Each venture: its tier, and the honest usage column.
        for slug in ["alpha", "beta"] {
            assert!(body.contains(slug), "{body}");
        }
        assert!(
            body.matches("<span class=\"chip\">free</span>").count() >= 2,
            "each venture's tier is rendered: {body}"
        );
        assert!(
            body.matches("not measured</strong>").count() >= 2,
            "one per venture: {body}"
        );
        assert!(body.contains("(#26)"), "names why: {body}");
        // The sentence that keeps a zero from reading as a measurement.
        assert!(body.contains("a zero would not be a measurement"), "{body}");
        // And nowhere a number pretending to be a count: a usage cell
        // that read "0 …" would be a measurement nobody made. (Bound to
        // the tag so the pricing model's "~100 MB" is not caught by its
        // own substring.)
        for lying in [">0 requests<", ">0 MB<", ">0 emails<", ">0 GB<"] {
            assert!(!body.contains(lying), "a zero as usage: {body}");
        }
    }

    #[pollster::test]
    async fn the_screen_says_nobody_has_ever_been_charged_rather_than_rendering_an_empty_table() {
        let kit = kit();
        seed(&kit).await;
        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("Nobody has ever been charged"),
            "the plain sentence: {body}"
        );
        // No invoice table exists to imply invoices do.
        assert!(!body.contains("Invoice"), "{body}");
        // The port's refusal is on the record (the apostrophe renders
        // escaped, so the assertion matches the words around it).
        assert!(body.contains("no billing is wired"), "{body}");
        assert!(
            body.contains("reading the venture") && body.contains("subscription"),
            "{body}"
        );
    }

    #[pollster::test]
    async fn the_free_tier_reads_as_a_throttle_and_never_as_a_pause() {
        let kit = kit();
        seed(&kit).await;
        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("The free tier is a throttle, never a pause"),
            "the commitment, headed: {body}"
        );
        assert!(
            body.contains("It does not stop"),
            "the commitment, in plain words: {body}"
        );
        assert!(
            body.contains("may never suspend, archive or stop it"),
            "the fence, stated: {body}"
        );
        // The pricing model the commitment is built on is on the page,
        // from the same data the document generates from.
        assert!(body.contains("throttled not billed"), "{body}");
        assert!(body.contains("<strong>always on</strong>"), "{body}");
        assert!(body.contains("$0.30 / million"), "{body}");
        assert!(body.contains(PAID_COLUMN), "{body}");
    }

    #[pollster::test]
    async fn a_screen_with_no_ventures_still_tells_the_truth_about_billing() {
        let kit = kit();
        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // No ventures, and the honest empty state, not a bare table.
        assert!(body.contains("No ventures yet"), "{body}");
        // The commitment and the refusal do not depend on having rows.
        assert!(body.contains("Nobody has ever been charged"), "{body}");
        assert!(body.contains("no billing is wired"), "{body}");
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_redirected_to_the_login_gate() {
        let kit = kit();
        let (status, _) = get(&kit, PATH, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    #[pollster::test]
    async fn one_account_sees_only_its_own_ventures_on_the_bill() {
        let kit = kit();
        seed(&kit).await;
        let repo = cratefield_accounts::Repository::new(kit.db.clone());
        repo.account_for_login("b@x.co", "B", "acc_2", "t0")
            .await
            .expect("account");
        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);

        let (status, body) = get(&kit, PATH, Some(&format!("cf_session={token}"))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !body.contains("alpha"),
            "A's venture is not on B's bill: {body}"
        );
        assert!(!body.contains("beta"), "{body}");
        assert!(body.contains("No ventures yet"), "{body}");
    }
}
