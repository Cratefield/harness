//! The Domains screen.
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
const SLUG: &str = "domains";

const PLANNED: Planned = Planned {
    title: "Domains",
    purpose: "Put a venture on a customer's own domain through Cloudflare for SaaS: add the hostname, show the DNS record to create, verify it, issue the certificate, and show the status while it settles.",
    instead: "You add the custom domain in Cloudflare yourself.",
    issue: Some(30),
};

pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    render_page(&state, &headers, SLUG, &PLANNED)
}
