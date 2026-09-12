//! The page a screen shows until it is built, and the shape a screen's
//! own file fills in.
//!
//! Every account-level screen owns a file next to this one, and that file
//! is the only thing a person has to change to build that screen: its
//! route and its place in the navigation already exist
//! ([`SCREENS`](crate::SCREENS)), so the work is to stop calling
//! [`render`] and render the real thing instead. That is deliberate — six
//! of these were being built at once, from six worktrees, and a single
//! shared table of screens would have made every one of them collide with
//! the other five in the same twenty lines.
//!
//! The page itself says three things: that the screen is not built, what
//! to do today instead, and which issue specifies it. A navigation entry
//! that leads to a blank page lies in one direction and a missing entry
//! lies in the other; this lies in neither. The copy is the site's own —
//! the preview at cratefield.com/dashboard/ already makes these promises,
//! and product and marketing disagreeing about what is built is its own
//! kind of lie.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use cratefield_chrome::{Page, escape, render};

use crate::{DashboardState, account_nav, current_session, frame, guard};

/// What a screen that is not built yet says for itself.
pub(crate) struct Planned {
    pub(crate) title: &'static str,
    /// What the screen is for, in a sentence.
    pub(crate) purpose: &'static str,
    /// What an operator does today instead. Usually a command.
    pub(crate) instead: &'static str,
    /// The issue that specifies it, in `Cratefield/control-plane`.
    pub(crate) issue: Option<u32>,
}

/// Renders one planned screen, guarded like every other account-level
/// page: the page names the operator, so it needs the session the guard
/// proves.
pub(crate) fn render_page(
    state: &State<Arc<DashboardState>>,
    headers: &HeaderMap,
    slug: &str,
    screen: &Planned,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, headers) {
        return redirect;
    }
    let session = current_session(ctx, headers).expect("guard proved a session");

    let issue = match screen.issue {
        Some(number) => format!(
            " <a href=\"https://github.com/Cratefield/control-plane/issues/{number}\" \
             rel=\"noopener\">The issue that specifies it.</a>"
        ),
        // One of these has no issue yet, and saying so is better than
        // linking one that does not exist.
        None => String::from(" No issue specifies it yet."),
    };

    let body = format!(
        "<p class=\"dash__banner\"><span class=\"chip\">Planned</span>\
         <strong>Not built.</strong> Today you do this instead: {instead}{issue}</p>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">What it will do</p>\
         <p class=\"dash__note\">{purpose}</p></div>\
         <p class=\"dash__note\">This page exists so the navigation does not lie in \
         either direction: the screen is in the design, it is not in the product, and \
         the thing you can do today is written down rather than left for you to find.</p>",
        instead = escape(screen.instead),
        purpose = escape(screen.purpose),
    );

    Html(render(&Page {
        title: screen.title,
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<div class=\"page-h\"><h1>{title}</h1><span class=\"chip\">Planned</span></div>\
             <p class=\"lede\">Not built yet. What it will do, and what to do \
             meanwhile.</p>{frame}",
            title = escape(screen.title),
            frame = frame(&account_nav(slug), screen.title, &body),
        ),
    }))
    .into_response()
}
