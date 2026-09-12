//! The Deploys screen.
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
const SLUG: &str = "deploys";

const PLANNED: Planned = Planned {
    title: "Deploys",
    purpose: "Every deploy of a venture, what module set it carried, and which one is serving now. Waiting on the same thing everything else here waits on: no Deployer talks to Cloudflare yet, so there are no deploys to list.",
    instead: "You run the build on your own machine and deploy with `wrangler`.",
    issue: Some(26),
};

pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    render_page(&state, &headers, SLUG, &PLANNED)
}
