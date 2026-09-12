//! The Backups screen.
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
const SLUG: &str = "backups";

const PLANNED: Planned = Planned {
    title: "Backups",
    purpose: "Point-in-time recovery inside D1's Time Travel window, a scheduled export to R2 for anything older, and the last successful backup shown here. A backup that has never been restored is not a backup, so the restore path is part of the work.",
    instead: "You export with `fz data export` and keep the file.",
    issue: Some(29),
};

pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    render_page(&state, &headers, SLUG, &PLANNED)
}
