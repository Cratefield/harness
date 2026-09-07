//! Account linking: one user, many identities (issue #22).
//!
//! Every login method ends here. A provider hands over an identity, and
//! this decides whether it belongs to somebody we already know or to
//! somebody new. **Getting that wrong in the permissive direction is an
//! account takeover**: an attacker who controls an address at one
//! provider signs in as the victim who used that address at another.
//!
//! So the rules are deliberately strict, and they run in order:
//!
//! 1. **Seen this exact identity before** — `(provider, subject)` — that
//!    is the user. Nothing else is consulted.
//! 2. **Somebody is signed in** — the identity is linked to them, after
//!    they confirm it. This is the only way to add a provider to an
//!    existing account, and it is safe because the person proved they
//!    hold the account before the new identity arrived.
//! 3. **The email matches, and both sides are verified** — link and log
//!    in, then tell the address it happened. Verified on *both* sides is
//!    what makes this safe: the provider vouches that the person holds
//!    the address, and we already vouched for the same thing.
//! 4. **Otherwise** — a new user. If an unverified address collides with
//!    an existing account we refuse to guess and say so, rather than
//!    silently creating a duplicate the person will not understand.
//!
//! Apple's private relay addresses never satisfy rule 3. They are
//! per-app aliases, so two different people can hold relay addresses
//! that look equally plausible, and a relay address tells us nothing
//! about who controls the real mailbox behind it (ADR 0100).

use cratefield_core::{Clock, Database, DbError, IdGen};

use crate::store::{self, IdentityRow, UserRow};

/// Apple's per-app alias domain. An address here identifies an Apple
/// relay, never a mailbox we can reason about.
pub const APPLE_PRIVATE_RELAY_DOMAIN: &str = "privaterelay.appleid.com";

/// What a provider hands over after a successful authorization.
#[derive(Debug, Clone)]
pub struct IncomingIdentity<'a> {
    /// `google`, `apple`, `meta`, `password`, `magic_link`, `passkey`.
    pub provider: &'a str,
    /// The provider's stable id for this person: OIDC `sub`, a Graph id,
    /// or the normalized address for password and magic-link.
    pub subject: &'a str,
    /// The address the provider reported, already normalized.
    pub email: Option<&'a str>,
    /// Whether **the provider** vouches that this person holds the
    /// address. A provider that does not say is not verified.
    pub email_verified: bool,
    /// The display name, which for Apple arrives only on the very first
    /// authorization and never again (ADR 0100).
    pub name: Option<&'a str>,
}

/// What the caller should do with the incoming identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Rule 1: a known identity. Log in.
    Known { user_id: String },
    /// Rule 2: link to the signed-in user once they confirm. The caller
    /// renders the confirmation and calls [`link`] on approval.
    ConfirmLink { user_id: String },
    /// Rule 3: auto-linked to an existing account on a verified address
    /// match. The caller should send the notification described in
    /// [`Outcome::AutoLinked::notify_email`].
    AutoLinked {
        user_id: String,
        /// The address to tell, because an account just gained a way in.
        notify_email: String,
    },
    /// Rule 4: nobody matches. Create a user and link.
    NewUser,
    /// Rule 4, collision case: an account holds this address, but it is
    /// not verified on both sides, so we will not guess. The person is
    /// told to sign in the way they already can and link from there.
    ExistingAccountUnverified,
}

/// Whether an address is an Apple private relay alias.
#[must_use]
pub fn is_apple_private_relay(email: &str) -> bool {
    email
        .rsplit_once('@')
        .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(APPLE_PRIVATE_RELAY_DOMAIN))
}

/// Applies the rules above.
///
/// `current_user` is the signed-in user, if any: its presence is what
/// makes rule 2 available, and it is the only path that links a
/// provider to an account without an email match.
///
/// # Errors
///
/// [`DbError`] when a lookup fails. A failure is never treated as "no
/// match" — that would turn a database blip into a duplicate account.
pub async fn resolve(
    db: &dyn Database,
    incoming: &IncomingIdentity<'_>,
    current_user: Option<&str>,
) -> Result<Outcome, DbError> {
    // Rule 1. The identity we have seen before wins over everything,
    // including a session: signing in with a second account while
    // holding a first must not link them.
    if let Some(existing) =
        store::identity_by_provider_subject(db, incoming.provider, incoming.subject).await?
    {
        return Ok(Outcome::Known {
            user_id: existing.user_id,
        });
    }

    // Rule 2. Someone is signed in, so they can vouch for themselves.
    if let Some(user_id) = current_user {
        return Ok(Outcome::ConfirmLink {
            user_id: user_id.to_owned(),
        });
    }

    // Rules 3 and 4 need an address to compare at all.
    let Some(email) = incoming.email else {
        return Ok(Outcome::NewUser);
    };

    // A relay address is not evidence about a mailbox, so it can never
    // match an existing account. It still becomes a new user's identity
    // — Apple sign-in works, it just never merges accounts.
    if is_apple_private_relay(email) {
        return Ok(Outcome::NewUser);
    }

    let Some(existing) = store::user_by_primary_email(db, email).await? else {
        return Ok(Outcome::NewUser);
    };

    // Rule 3, and the whole reason this function is careful. BOTH sides
    // must be verified. The provider's word alone is not enough: an
    // attacker who registers the victim's address at a provider that
    // does not verify addresses would otherwise walk into the account.
    // Our word alone is not enough either, for the mirror reason.
    if incoming.email_verified && existing.primary_email_verified {
        return Ok(Outcome::AutoLinked {
            user_id: existing.id,
            notify_email: email.to_owned(),
        });
    }

    // An account holds the address but the evidence is not there.
    // Refusing to guess is the point: creating a second account here
    // silently splits a person in two, and linking would be the
    // takeover.
    Ok(Outcome::ExistingAccountUnverified)
}

/// Writes the identity row that [`resolve`] decided on.
///
/// Call this after `Known`, `ConfirmLink` (once confirmed) or
/// `AutoLinked`, and after creating the user for `NewUser`.
///
/// # Errors
///
/// [`DbError`] when the insert fails, including the unique violation
/// that means the identity was linked concurrently.
pub async fn link(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
    incoming: &IncomingIdentity<'_>,
) -> Result<IdentityRow, DbError> {
    let row = IdentityRow {
        id: id_gen.ulid(),
        user_id: user_id.to_owned(),
        provider: incoming.provider.to_owned(),
        provider_subject: incoming.subject.to_owned(),
        email: incoming.email.map(str::to_owned),
        email_verified: incoming.email_verified,
        // Captured now or never: Apple sends the name only on the first
        // authorization (ADR 0100).
        name_at_link: incoming.name.map(str::to_owned),
        created_at: crate::sessions::iso(clock.now()),
        last_login_at: None,
    };
    store::insert_identity(db, &row).await?;
    Ok(row)
}

/// Why an unlink was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnlinkError {
    #[error("that identity does not belong to this user")]
    NotFound,
    #[error("this is the only way into the account")]
    LastMethod,
}

/// Removes one linked identity.
///
/// Refuses to remove the last way into an account: a person who unlinks
/// their only provider is locked out, and no amount of support tooling
/// makes that a good experience. Credentials (a password or a passkey)
/// count as ways in, so an account with a password may unlink its last
/// provider.
///
/// # Errors
///
/// [`UnlinkError::NotFound`] when the identity is not this user's, and
/// [`UnlinkError::LastMethod`] when removing it would lock them out.
pub async fn unlink(
    db: &dyn Database,
    user_id: &str,
    identity_id: &str,
) -> Result<Result<(), UnlinkError>, DbError> {
    let identities = store::identities_by_user(db, user_id).await?;
    if !identities.iter().any(|row| row.id == identity_id) {
        return Ok(Err(UnlinkError::NotFound));
    }
    let credentials = store::credentials_by_user(db, user_id).await?;
    if identities.len() <= 1 && credentials.is_empty() {
        return Ok(Err(UnlinkError::LastMethod));
    }
    store::delete_identity(db, identity_id).await?;
    Ok(Ok(()))
}

/// Creates the user an [`Outcome::NewUser`] calls for.
///
/// The address is stored as the primary email, and is marked verified
/// only when the provider vouched for it — a provider that does not
/// verify addresses must not be able to hand us a "verified" one.
///
/// # Errors
///
/// [`DbError`] when the insert fails.
pub async fn create_user(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    incoming: &IncomingIdentity<'_>,
) -> Result<UserRow, DbError> {
    let now = crate::sessions::iso(clock.now());
    let row = UserRow {
        id: id_gen.ulid(),
        display_name: incoming.name.map(str::to_owned),
        primary_email: incoming.email.map(str::to_owned),
        primary_email_verified: incoming.email.is_some() && incoming.email_verified,
        status: "active".to_owned(),
        created_at: now.clone(),
        updated_at: now,
    };
    store::insert_user(db, &row).await?;
    Ok(row)
}
