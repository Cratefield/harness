//! Turning a verified provider identity into a session (issues #15, #22).
//!
//! The decision of *which* account an identity belongs to is not made here.
//! `auth-core::linking` owns those rules — they are the same for Google,
//! Apple, Meta and every method that arrives with an email — and this module
//! only carries out what they return.

use factory0_auth_core::linking::{IncomingIdentity, Outcome, create_user, link, resolve};
use factory0_auth_core::{
    IssuedSession, Login, SessionError, delete_user, identity_by_provider_subject,
    issue as issue_session, set_cookie, touch_identity_login,
};
use factory0_core::{Clock, Database, IdGen, ModuleContext, Problem, Scope};
use serde_json::json;

use crate::provider::Provider;

pub(crate) const EVENT_LOGGED_IN: &str = "auth-oidc.logged_in";
pub(crate) const EVENT_AUTO_LINKED: &str = "auth-oidc.auto_linked";

/// RFC 8176: this login was a federated assertion from a third party. No
/// `mfa`, whatever the provider did behind its own door: we did not see it.
const AMR: [&str; 1] = ["federated"];

/// What the provider told us, already normalized.
pub(crate) struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

/// Where a completed callback should send the browser, or what to tell the
/// person when there is nothing to send them to yet.
pub(crate) enum Completed {
    /// Signed in. The caller sets the cookie and redirects.
    SignedIn { session: IssuedSession },
    /// The linking rules will not guess (`ExistingAccountUnverified`), or
    /// the person must approve a link (`ConfirmLink`). Both need a page and
    /// a decision this module does not own.
    NeedsPerson { message: &'static str },
}

/// What the callback knows about the browser at the other end.
pub(crate) struct Caller<'a> {
    /// The signed-in user, when the callback arrived with a live session:
    /// that is a person adding a provider, and the linking rules need it.
    pub current_user: Option<&'a str>,
    /// The session cookie the request presented, revoked before a new
    /// session exists (auth-core's fixation defence).
    pub presented_cookie: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// The ports this step needs, gathered so the signature stays readable.
pub(crate) struct Ports<'a> {
    pub db: &'a dyn Database,
    pub clock: &'a dyn Clock,
    pub id_gen: &'a dyn IdGen,
}

/// Applies the linking rules and, when they say so, issues a session.
pub(crate) async fn complete(
    ctx: &ModuleContext,
    scope: &Scope,
    ports: &Ports<'_>,
    provider: &Provider,
    identity: &Identity,
    caller: &Caller<'_>,
) -> Result<Completed, Problem> {
    let Ports { db, clock, id_gen } = *ports;
    let incoming = IncomingIdentity {
        provider: provider.slug,
        subject: &identity.subject,
        email: identity.email.as_deref(),
        email_verified: identity.email_verified,
        name: identity.name.as_deref(),
    };

    let outcome = resolve(db, &incoming, caller.current_user)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "account linking could not be resolved");
            Problem::internal().instance(&scope.request_id)
        })?;

    let user_id = match outcome {
        Outcome::Known { user_id } => {
            // The column exists so the account page can say when a provider
            // was last used; nothing else writes it.
            match identity_by_provider_subject(db, provider.slug, &identity.subject).await {
                Ok(Some(row)) => {
                    if let Err(err) =
                        touch_identity_login(db, &row.id, &crate::iso(clock.now())).await
                    {
                        tracing::warn!(error = %err, "could not record the last login");
                    }
                }
                Ok(None) => {}
                Err(err) => tracing::warn!(error = %err, "could not read the identity"),
            }
            user_id
        }
        Outcome::AutoLinked {
            user_id,
            notify_email,
        } => {
            // The account just gained a way in, so somebody has to be told.
            // Sending the mail is not this module's job; saying it happened
            // is, and a mail module can subscribe.
            ctx.events.emit_in(
                scope,
                EVENT_AUTO_LINKED,
                json!({
                    "user_id": user_id,
                    "provider": provider.slug,
                    "notify_email": notify_email,
                }),
            );
            link(db, clock, id_gen, &user_id, &incoming)
                .await
                .map_err(|err| {
                    tracing::error!(error = %err, "could not link the identity");
                    Problem::internal().instance(&scope.request_id)
                })?;
            user_id
        }
        Outcome::NewUser => new_user(ports, scope, &incoming).await?,
        // Both of these need a person to decide something, and the page
        // that would let them does not exist yet (#22 owns the confirm
        // step). Say so plainly rather than guessing an account.
        Outcome::ConfirmLink { .. } => {
            return Ok(Completed::NeedsPerson {
                message: "That account is already signed in here. Linking this provider needs \
                          confirming from your account page, which is not built yet.",
            });
        }
        Outcome::ExistingAccountUnverified => {
            return Ok(Completed::NeedsPerson {
                message: "An account already uses that email address, and neither side has \
                          verified it. Sign in the way you already can, then link this provider \
                          from there.",
            });
        }
    };

    let session = issue_session(
        db,
        clock,
        id_gen,
        Login {
            user_id: &user_id,
            ip: caller.ip,
            user_agent: caller.user_agent,
            presented_cookie: caller.presented_cookie,
            amr: &AMR,
        },
    )
    .await
    .map_err(|err| match err {
        // The account exists but is switched off. Same answer as any other
        // refused callback: it is not a caller's business which.
        SessionError::NotActive => {
            tracing::warn!(user = %user_id, "a disabled account signed in through a provider");
            Problem::new(&crate::CALLBACK_REFUSED).instance(&scope.request_id)
        }
        err => {
            tracing::error!(error = %err, "could not issue a session");
            Problem::internal().instance(&scope.request_id)
        }
    })?;

    ctx.events.emit_in(
        scope,
        EVENT_LOGGED_IN,
        json!({
            "user_id": user_id,
            "provider": provider.slug,
            "session_id": session.session_id,
        }),
    );

    Ok(Completed::SignedIn { session })
}

/// Creates the account a first sign-in earns, and links the identity to it.
///
/// Not atomic, because the `Database` port has no transaction that spans
/// two statements. Two first logins for the same provider subject can race,
/// and the loser's `link` hits the unique constraint *after* its user row
/// exists. That row would carry an email, no identity, and no way to reach
/// it — and a later verified-email match from another provider would link a
/// stranger to it. So the loser cleans up after itself and takes the
/// winner's account.
async fn new_user(
    ports: &Ports<'_>,
    scope: &Scope,
    incoming: &IncomingIdentity<'_>,
) -> Result<String, Problem> {
    let Ports { db, clock, id_gen } = *ports;
    // auth-core's own, rather than a second copy of the same insert: it is
    // where the rule that an absent address is never "verified" lives.
    let user = create_user(db, clock, id_gen, incoming)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not create the user");
            Problem::internal().instance(&scope.request_id)
        })?;

    if let Err(err) = link(db, clock, id_gen, &user.id, incoming).await {
        tracing::warn!(error = %err, "linking a new user failed; undoing the account");
        if let Err(err) = delete_user(db, &user.id).await {
            tracing::error!(error = %err, "could not undo the orphaned account");
        }
        // Somebody else got there first. Ask again: by now the identity
        // exists and the answer is their account.
        return match resolve(db, incoming, None).await {
            Ok(Outcome::Known { user_id }) => Ok(user_id),
            _ => Err(Problem::internal().instance(&scope.request_id)),
        };
    }
    Ok(user.id)
}

/// The `Set-Cookie` value for an issued session.
pub(crate) fn session_cookie(session: &IssuedSession) -> String {
    set_cookie(&session.value)
}
