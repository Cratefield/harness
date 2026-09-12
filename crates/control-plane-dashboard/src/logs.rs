//! The Logs screen.
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
const SLUG: &str = "logs";

const PLANNED: Planned = Planned {
    title: "Logs",
    purpose: "A venture's request and error logs, kept long enough to look at after the fact. Nothing retains them today, which is the part that needs building — not the screen.",
    instead: "You use `wrangler tail`, which shows the live stream and keeps nothing.",
    issue: None,
};

pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    render_page(&state, &headers, SLUG, &PLANNED)
}
