//! What to tell someone who has to fetch a credential by hand.
//!
//! Stripe connects by OAuth ([`crate::stripe`]) and nothing is pasted.
//! The other two cannot, and it is worth being precise about why, because
//! it is not an oversight either provider will fix:
//!
//! - **Google.** OAuth grants access to *data*. It does not provision an
//!   OAuth *client*, and a venture needs its own client for its end users
//!   to log in. No flow hands a third party a client secret.
//! - **Resend.** No OAuth at all — authentication is a bearer API key the
//!   account owner creates.
//!
//! So for these the job is not to remove the paste but to remove the ways
//! it goes wrong. Three of them, in the order they bite:
//!
//! 1. Not knowing which page to open. Every guide carries a deep link to
//!    the exact one, not a documentation home page.
//! 2. **Not registering the redirect URI.** This is the one that actually
//!    costs people an afternoon: Google refuses an authorization whose
//!    redirect is not registered, and the error arrives at the end of the
//!    flow, in the browser, phrased as `redirect_uri_mismatch`. The guide
//!    carries the exact string to paste *into Google*, so it can be shown
//!    beside the field rather than derived by the reader.
//! 3. Pasting the wrong value — an API key where a client id goes, a test
//!    key in a production venture. [`Expectation`] is the shape check,
//!    and it is the same one storage applies, so a value that passes the
//!    guide cannot then be refused on submit.

use crate::ConnectionKind;

/// Where the Google OAuth client is created. The credentials page, not
/// the console root: a link that lands somewhere general is a link the
/// reader has to navigate from.
const GOOGLE_CONSOLE: &str = "https://console.cloud.google.com/apis/credentials";
/// Resend's API keys page, as their own documentation links it.
const RESEND_CONSOLE: &str = "https://resend.com/api-keys";

/// What a pasted value should look like.
///
/// Split into a rule that refuses and a rule that only warns, because a
/// shape check that is wrong refuses a valid credential — and a guard
/// that cries wolf is one somebody turns off. A prefix is a strong signal
/// and is enforced; anything softer is advice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// What the value is, named in every refusal: a reason that says only
    /// "wrong shape" leaves the reader guessing which of two fields they
    /// filled in wrongly.
    pub label: &'static str,
    /// A required suffix, if the provider guarantees one.
    pub suffix: Option<&'static str>,
    /// A required prefix, if the provider guarantees one.
    pub prefix: Option<&'static str>,
    /// Shown beside the field: what a correct value looks like.
    pub example: &'static str,
}

impl Expectation {
    /// Anything non-empty. For a provider whose key shape is not
    /// documented stably enough to refuse on.
    #[must_use]
    pub const fn any(label: &'static str, example: &'static str) -> Self {
        Self {
            label,
            suffix: None,
            prefix: None,
            example,
        }
    }

    /// Why `value` is not acceptable, or `None` if it is.
    ///
    /// The same check the store applies, so a value the guide accepts is
    /// never refused on submit.
    #[must_use]
    pub fn refuse(&self, value: &str) -> Option<String> {
        let value = value.trim();
        if value.is_empty() {
            return Some(format!("the {} is empty", self.label));
        }
        if let Some(prefix) = self.prefix
            && !value.starts_with(prefix)
        {
            return Some(format!(
                "that is not a {}: it should start with `{prefix}` (for example {})",
                self.label, self.example
            ));
        }
        if let Some(suffix) = self.suffix
            && !value.ends_with(suffix)
        {
            return Some(format!(
                "that is not a {}: it should end with `{suffix}` (for example {})",
                self.label, self.example
            ));
        }
        None
    }
}

/// Everything a wizard, a CLI prompt or an agent needs to walk somebody
/// through fetching one credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guidance {
    /// One line: what is being fetched and what it is for.
    pub summary: String,
    /// The exact page to open.
    pub console_url: &'static str,
    /// Ordered, imperative, each one a thing to do in the provider's UI.
    pub steps: Vec<String>,
    /// A value that must be pasted **into the provider**, not back here.
    /// Google's authorized redirect URI is the whole reason this field
    /// exists; a surface should render it as copyable text.
    pub register_back: Option<String>,
    /// The shape of the value to bring back.
    pub expects: Expectation,
}

impl ConnectionKind {
    /// How to fetch this credential by hand.
    ///
    /// `callback_base` is the venture's own public URL — the redirect URI
    /// Google must be told about is derived from it rather than written
    /// down twice.
    #[must_use]
    pub fn guidance(&self, callback_base: &str) -> Guidance {
        let base = callback_base.trim_end_matches('/');
        match self {
            ConnectionKind::VentureGoogleOauth => {
                let redirect = format!("{base}/v1/auth/oidc/callback");
                Guidance {
                    summary: "A Google OAuth client, so your users can sign in with Google."
                        .to_owned(),
                    console_url: GOOGLE_CONSOLE,
                    steps: vec![
                        "Choose the Google Cloud project this venture belongs to.".to_owned(),
                        "Create credentials, then OAuth client ID, then Web application."
                            .to_owned(),
                        format!(
                            "Under Authorized redirect URIs, add exactly: {redirect} — Google \
                             refuses any redirect it has not been told about, and it tells you \
                             so only at the end of the sign-in, as `redirect_uri_mismatch`."
                        ),
                        "Copy the client ID and the client secret back here.".to_owned(),
                    ],
                    register_back: Some(redirect),
                    expects: Expectation {
                        label: "Google OAuth client id",
                        // One definition, shared with the store's check.
                        suffix: Some(crate::GOOGLE_CLIENT_ID_SUFFIX),
                        prefix: None,
                        example: "1234567890-abc.apps.googleusercontent.com",
                    },
                }
            }
            ConnectionKind::ModuleKey { module, service } if service == "resend" => Guidance {
                summary: format!("A Resend API key, so `{module}` can send mail."),
                console_url: RESEND_CONSOLE,
                steps: vec![
                    "Create an API key with Sending access.".to_owned(),
                    "Copy it now — Resend shows a key once, at creation.".to_owned(),
                ],
                register_back: None,
                expects: Expectation {
                    label: "Resend API key",
                    suffix: None,
                    prefix: Some("re_"),
                    example: "re_123abc…",
                },
            },
            ConnectionKind::ModuleKey { module, service } => Guidance {
                summary: format!("A {service} API key for `{module}`."),
                // No deep link invented for a service this does not know:
                // a wrong link is worse than none.
                console_url: "",
                steps: vec![format!(
                    "Create an API key in your {service} account and copy it back here."
                )],
                register_back: None,
                expects: Expectation::any("API key", "a key from your provider"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn google() -> Guidance {
        ConnectionKind::VentureGoogleOauth.guidance("https://acme.example/")
    }

    #[test]
    fn the_google_guide_hands_over_the_redirect_uri_to_register() {
        // The step that actually costs people an afternoon. It has to be
        // an exact string a surface can render as copyable text, not a
        // sentence the reader assembles.
        let guide = google();
        assert_eq!(
            guide.register_back.as_deref(),
            Some("https://acme.example/v1/auth/oidc/callback"),
            "the trailing slash on the base must not double up"
        );
        assert!(
            guide
                .steps
                .iter()
                .any(|step| step.contains("redirect_uri_mismatch")),
            "the guide names the error Google will actually show: {:?}",
            guide.steps
        );
        assert_eq!(guide.console_url, GOOGLE_CONSOLE);
    }

    #[test]
    fn the_guide_and_the_store_refuse_the_same_values() {
        // A value the wizard accepted must never be refused on submit;
        // that is the whole reason `Expectation` is shared rather than
        // the check being written twice.
        let expects = google().expects;
        assert!(
            expects
                .refuse("1234567890-abc.apps.googleusercontent.com")
                .is_none()
        );
        assert!(expects.refuse("   ").is_some(), "empty is refused");

        let wrong = expects
            .refuse("re_an_api_key")
            .expect("an API key is not a client id");
        assert!(
            wrong.contains("Google OAuth client id"),
            "the reason names which credential: {wrong}"
        );
        assert!(
            wrong.contains(".apps.googleusercontent.com"),
            "and what was expected: {wrong}"
        );
        assert!(
            wrong.contains("1234567890-abc"),
            "and shows an example: {wrong}"
        );
    }

    #[test]
    fn resend_is_guided_to_the_page_its_own_docs_link() {
        let guide = ConnectionKind::ModuleKey {
            module: "email-signup".to_owned(),
            service: "resend".to_owned(),
        }
        .guidance("https://acme.example");
        assert_eq!(guide.console_url, RESEND_CONSOLE);
        assert!(guide.register_back.is_none(), "nothing to register back");
        assert!(
            guide.steps.iter().any(|step| step.contains("once")),
            "Resend shows a key once; the guide says so: {:?}",
            guide.steps
        );
        assert!(guide.expects.refuse("re_123abc").is_none());
        assert!(
            guide.expects.refuse("sk_live_stripe").is_some(),
            "a key from the wrong provider is refused"
        );
    }

    #[test]
    fn an_unknown_service_invents_no_link() {
        // A wrong deep link is worse than none: it sends someone to a
        // page that cannot produce what they were asked for.
        let guide = ConnectionKind::ModuleKey {
            module: "widgets".to_owned(),
            service: "acme-corp".to_owned(),
        }
        .guidance("https://acme.example");
        assert_eq!(guide.console_url, "");
        assert!(
            guide.expects.refuse("anything-non-empty").is_none(),
            "an undocumented key shape is not refused on a guess"
        );
        assert!(guide.expects.refuse("").is_some());
    }
}
