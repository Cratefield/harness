//! The Billing screen.
//!
//! Not built yet: it renders the planned page from the facts below. To
//! build it, replace the body of [`screen`] — its route and its place in
//! the navigation already exist, so this file is the only one that has to
//! change. See [`crate::planned`] for why it is arranged that way.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;

use crate::DashboardState;
use crate::planned::{Planned, render_page};

/// The path segment under `/v1/dashboard`.
const SLUG: &str = "billing";

const PLANNED: Planned = Planned {
    title: "Billing",
    purpose: "What a venture costs and what it is being charged: a Stripe subscription per venture, per-venture counters for requests, storage and email, and a free tier enforced by throttling rather than by a bill. The free tier stays on — the throttle must never become a pause.",
    instead: "Nothing: there is nothing to pay for yet.",
    issue: Some(27),
};

pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    render_page(&state, &headers, SLUG, &PLANNED)
}
