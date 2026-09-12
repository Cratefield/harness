//! The Environments screen.
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
const SLUG: &str = "environments";

const PLANNED: Planned = Planned {
    title: "Environments",
    purpose: "A staging venture alongside production with its own database and secrets, and a promotion that moves a module set and its migrations from one to the other. Without it every schema change is tested in production.",
    instead: "You deploy a second backend and wire it up yourself.",
    issue: Some(31),
};

pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    render_page(&state, &headers, SLUG, &PLANNED)
}
