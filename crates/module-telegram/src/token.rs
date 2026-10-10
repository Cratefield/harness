//! The compact signed token an action button carries in its
//! `callback_data`, and the constant-time check that opens one.
//!
//! Telegram caps `callback_data` at **64 bytes**, so the Signer port's
//! tokens — and anything else a venture might already mint — do not fit.
//! A button instead carries a purpose-built token:
//!
//! ```text
//! a1.  <base64url, no pad, of:>
//!      action_id  [22 bytes]   the id's base64url text — the row key itself
//!      decision   [1 byte]     1 = approve, 0 = deny
//!      exp_unix   [4 bytes BE] when the button stops working
//!      tag        [12 bytes]   HMAC-SHA256, leftmost 12
//! ```
//!
//! The tag is over `"telegram.action"`, the action id text, the decision,
//! the expiry and the **intended Telegram user**, so a button forwarded
//! to a group is dead paper: anyone else pressing it fails the check
//! before the database is asked anything. The whole token is 39 bytes
//! with the prefix — well under the cap.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The prefix every action token starts with: what tells a callback query
/// apart from any other `data` a venture's buttons might carry.
pub const ACTION_TOKEN_PREFIX: &str = "a1.";

/// Base64url, no padding — the encoding of an action id and of a token's
/// payload. No pad keeps a 16-byte id at 22 characters and a whole token
/// well under Telegram's 64-byte `callback_data` cap.
pub(crate) fn b64url(bytes: &[u8]) -> String {
    BASE64URL.encode(bytes)
}

/// How many bytes of the HMAC tag ride in the token — 96 bits, plenty for
/// a token that expires within the hour.
const TAG_LEN: usize = 12;

/// One byte naming the decision, as the token carries it.
const APPROVE_BYTE: u8 = 1;
/// One byte naming the decision, as the token carries it.
const DENY_BYTE: u8 = 0;

/// The domain-separation prefix of every tag, so bytes minted for another
/// purpose in this deployment never verify here.
const TAG_CONTEXT: &[u8] = b"telegram.action";

/// Which button the token stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// The Approve button.
    Approve,
    /// The Deny button.
    Deny,
}

impl Decision {
    /// The one byte the token carries.
    fn byte(self) -> u8 {
        match self {
            Self::Approve => APPROVE_BYTE,
            Self::Deny => DENY_BYTE,
        }
    }

    /// The decision a token byte names; `None` for any other value.
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            APPROVE_BYTE => Some(Self::Approve),
            DENY_BYTE => Some(Self::Deny),
            _ => None,
        }
    }
}

/// What a token that opened says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The action row the button belongs to.
    pub action_id: String,
    /// Which button was pressed.
    pub decision: Decision,
    /// When the button stopped working, as Unix seconds.
    pub exp_unix: u32,
}

/// Mints the token for one button of an action prompt.
///
/// `action_id` is the base64url text the `telegram_actions` row is keyed
/// by; `telegram_user_id` is the person the button is being sent to —
/// the check binds it, so a forwarded button pressed by anyone else is
/// refused.
///
/// # Panics
///
/// Never: HMAC-SHA256 accepts keys of any length, so the key setup
/// cannot fail — the `expect` guards that invariant, nothing else.
#[must_use]
pub fn action_token(
    key: &[u8],
    action_id: &str,
    decision: Decision,
    exp_unix: u32,
    telegram_user_id: i64,
) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(TAG_CONTEXT);
    mac.update(action_id.as_bytes());
    mac.update(&[decision.byte()]);
    mac.update(&exp_unix.to_be_bytes());
    mac.update(&telegram_user_id.to_be_bytes());
    let tag = &mac.finalize().into_bytes()[..TAG_LEN];

    let mut payload = Vec::with_capacity(16 + 1 + 4 + TAG_LEN);
    payload.extend_from_slice(action_id.as_bytes());
    payload.push(decision.byte());
    payload.extend_from_slice(&exp_unix.to_be_bytes());
    payload.extend_from_slice(tag);
    format!("{ACTION_TOKEN_PREFIX}{}", BASE64URL.encode(payload))
}

/// Opens `token` as if it were pressed by `telegram_user_id`, at Unix
/// time `now_unix`. The tag check is constant-time (`Mac::verify_truncated_left`),
/// and an expired token is refused here so a stale button never reaches
/// the database.
///
/// The action id is returned but **not** looked up: whether the row
/// exists, is still pending and belongs to this Telegram user is the
/// caller's half of the check.
///
/// # Panics
///
/// Never: HMAC-SHA256 accepts keys of any length, so the key setup
/// cannot fail — the `expect` guards that invariant, nothing else.
#[must_use]
pub fn open_action_token(
    key: &[u8],
    token: &str,
    telegram_user_id: i64,
    now_unix: u32,
) -> Option<VerifiedToken> {
    // action_id (22 for the canonical id) | decision (1) | exp (4) | tag (12).
    // The id is variable-length text; the rest of the frame is fixed, so
    // its length falls out of the payload's.
    const FRAME: usize = 1 + 4 + TAG_LEN;

    let payload = BASE64URL
        .decode(token.strip_prefix(ACTION_TOKEN_PREFIX)?)
        .ok()?;
    if payload.len() < FRAME {
        return None;
    }
    let split = payload.len() - TAG_LEN;
    let (body, tag) = payload.split_at(split);
    let id_len = body.len().checked_sub(FRAME - TAG_LEN)?;
    let action_id = std::str::from_utf8(&body[..id_len]).ok()?;
    let decision = Decision::from_byte(body[id_len])?;
    let exp_unix = u32::from_be_bytes(body[id_len + 1..id_len + 5].try_into().ok()?);
    if now_unix >= exp_unix {
        return None;
    }

    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(TAG_CONTEXT);
    mac.update(action_id.as_bytes());
    mac.update(&[decision.byte()]);
    mac.update(&exp_unix.to_be_bytes());
    mac.update(&telegram_user_id.to_be_bytes());
    mac.verify_truncated_left(tag).ok()?;

    Some(VerifiedToken {
        action_id: action_id.to_owned(),
        decision,
        exp_unix,
    })
}

/// The `TELEGRAM_ACTION_SECRET` value as key bytes, `None` when absent or
/// blank — the fail-closed read every issuer and every tap goes through.
#[must_use]
pub fn action_key(config: &dyn cratefield_core::Config) -> Option<Vec<u8>> {
    config
        .get(crate::ACTION_SECRET_KEY)
        .filter(|secret| !secret.trim().is_empty())
        .map(String::into_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-action-secret";
    const ACTION: &str = "aGVsbG8td29ybGQtYWhlYWRsb3c"; // 16 bytes base64url
    const USER: i64 = 777;
    const EXP: u32 = 1_800_100_000;
    const NOW: u32 = 1_800_000_000;

    #[test]
    fn a_minted_token_opens_for_its_owner() {
        let token = action_token(KEY, ACTION, Decision::Approve, EXP, USER);
        assert!(token.starts_with(ACTION_TOKEN_PREFIX));
        assert!(token.len() <= 64, "Telegram's callback_data cap: {token}");

        let opened = open_action_token(KEY, &token, USER, NOW).expect("the owner's tap verifies");
        assert_eq!(opened.action_id, ACTION);
        assert_eq!(opened.decision, Decision::Approve);
        assert_eq!(opened.exp_unix, EXP);
    }

    #[test]
    fn the_other_button_is_a_different_token() {
        let approve = action_token(KEY, ACTION, Decision::Approve, EXP, USER);
        let deny = action_token(KEY, ACTION, Decision::Deny, EXP, USER);
        assert_ne!(approve, deny);
        assert_eq!(
            open_action_token(KEY, &deny, USER, NOW)
                .expect("deny verifies")
                .decision,
            Decision::Deny
        );
        // An approve token's bytes do not read as a deny.
        assert!(
            open_action_token(KEY, &approve, USER, NOW)
                .is_some_and(|opened| opened.decision == Decision::Approve)
        );
    }

    #[test]
    fn anyone_else_s_forward_is_refused() {
        let token = action_token(KEY, ACTION, Decision::Approve, EXP, USER);
        assert!(
            open_action_token(KEY, &token, 888, NOW).is_none(),
            "a tap by another Telegram user fails the tag"
        );
    }

    #[test]
    fn an_expired_or_tampered_token_is_refused() {
        let token = action_token(KEY, ACTION, Decision::Approve, EXP, USER);
        assert!(
            open_action_token(KEY, &token, USER, EXP).is_none(),
            "at expiry"
        );
        assert!(
            open_action_token(KEY, &token, USER, EXP - 1).is_some(),
            "one second before still works"
        );

        let mut bytes = token.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = bytes[last].wrapping_add(1);
        let tampered = String::from_utf8(bytes).expect("still ascii");
        assert!(open_action_token(KEY, &tampered, USER, NOW).is_none());

        assert!(open_action_token(KEY, "b1.not-a-token", USER, NOW).is_none());
        assert!(open_action_token(KEY, &format!("{ACTION_TOKEN_PREFIX}!!!!"), USER, NOW).is_none());
        assert!(
            open_action_token(
                b"other-key",
                &action_token(KEY, ACTION, Decision::Approve, EXP, USER),
                USER,
                NOW
            )
            .is_none()
        );
    }
}
