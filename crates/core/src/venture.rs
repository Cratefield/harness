//! The venture descriptor: who this backend belongs to (issue #2).

use crate::config::ConfigError;

/// Deployment environment. Mirrors the `ENV` config key; `Production`
/// drives the mandatory-captcha rule (architecture section 11).
///
/// Ordered least to most protected, so [`VentureEnv::strictest`] can take
/// the safer of two answers (issue #143).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum VentureEnv {
    #[default]
    Development,
    Staging,
    Production,
}

impl VentureEnv {
    pub fn as_str(&self) -> &'static str {
        match self {
            VentureEnv::Development => "development",
            VentureEnv::Staging => "staging",
            VentureEnv::Production => "production",
        }
    }

    /// The safer of two answers about one deployment (issue #143).
    ///
    /// A venture carries a **compiled** environment — a builder default
    /// the operator cannot change without a rebuild — while the
    /// deployment carries an `ENV` binding it can. They disagreed
    /// silently, and the disagreement always resolved toward the weaker
    /// answer: `ventures/cratefield-waitlist` ships `ENV = "production"`
    /// and never calls [`Venture::env`], so every production-only rule
    /// read `Development` and did not apply to the one venture actually
    /// in production. Neither source may downgrade the other: if either
    /// says `Production`, the deployment is production.
    #[must_use]
    pub fn strictest(self, other: Self) -> Self {
        self.max(other)
    }

    /// Parses the `ENV` config value; anything unknown is `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" => Some(VentureEnv::Development),
            "staging" => Some(VentureEnv::Staging),
            "production" => Some(VentureEnv::Production),
            _ => None,
        }
    }
}

/// Venture branding for mail templates (issue #12). Defaults are
/// text-only: factory-zero orange accent, no logo, no footer line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Brand {
    /// Accent colour as a `#rrggbb` string (links and rule lines).
    pub accent: String,
    /// Optional logo image URL; mails must read fine with images off.
    pub logo_url: Option<String>,
    /// Optional footer line (e.g. a company address).
    pub footer: Option<String>,
}

impl Default for Brand {
    fn default() -> Self {
        Self {
            accent: "#FF5A36".to_owned(),
            logo_url: None,
            footer: None,
        }
    }
}

/// Identity and CORS configuration for the venture this harness serves.
///
/// ```
/// use cratefield_core::Venture;
///
/// let v = Venture::new("factory0", "factory0.ventures")
///     .public_url("https://factory0.ventures")
///     .cors_origins(["https://factory0.ventures"]);
/// assert_eq!(v.name, "factory0");
/// assert_eq!(v.problem_type_base(), "https://factory0.ventures/problems/");
/// ```
#[derive(Debug, Clone)]
pub struct Venture {
    /// Kebab-case venture name (`factory0`).
    pub name: String,
    /// Apex domain (`factory0.ventures`); the API serves `api.<domain>`.
    pub domain: String,
    /// Absolute public URL the API is linked from.
    pub public_url: String,
    /// CORS allowlist. Never `*` (architecture section 6).
    pub cors_origins: Vec<String>,
    /// Deployment environment.
    pub env: VentureEnv,
    /// Mail branding (issue #12).
    pub brand: Brand,
    /// Explicit [`Venture::problem_type_base`] override, for a venture that
    /// serves its problems from somewhere other than `<public_url>/problems/`.
    pub problem_base: Option<String>,
}

impl Venture {
    pub fn new(name: impl Into<String>, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        Self {
            name: name.into(),
            public_url: format!("https://{domain}"),
            domain,
            cors_origins: Vec::new(),
            env: VentureEnv::default(),
            brand: Brand::default(),
            problem_base: None,
        }
    }

    #[must_use]
    pub fn public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = url.into();
        self
    }

    /// Overrides the base every problem `type` of this venture is served
    /// under (RFC 9457): the full base URI, ending in `/`. Unset, the base
    /// derives from [`Venture::public_url`] — see
    /// [`Venture::problem_type_base`].
    #[must_use]
    pub fn problem_base(mut self, url: impl Into<String>) -> Self {
        self.problem_base = Some(url.into());
        self
    }

    /// The base URI every problem `type` of this venture is served under:
    /// the [`Venture::problem_base`] override when set, else
    /// `<public_url>/problems/`, else `about:blank`.
    ///
    /// A venture with no public URL has no URI of its own to name, and it
    /// must never name another venture's domain: RFC 9457 §4.2.1 reserves
    /// `about:blank` for exactly this, so that is the fallback. Callers
    /// branch on the slug — the part after the base; under the default base
    /// everything after `/problems/`, `auth/…` namespaces included — which
    /// is the stable part
    /// (docs/ERRORS.md).
    ///
    /// ```
    /// use cratefield_core::Venture;
    ///
    /// // The default: under the venture's own public URL.
    /// let v = Venture::new("acme", "acme.example").public_url("https://acme.example/");
    /// assert_eq!(v.problem_type_base(), "https://acme.example/problems/");
    ///
    /// // An explicit override wins, normalized to one trailing slash.
    /// let v = v.problem_base("https://errors.acme.example/types/");
    /// assert_eq!(v.problem_type_base(), "https://errors.acme.example/types/");
    /// let v = v.problem_base("https://errors.acme.example/types");
    /// assert_eq!(v.problem_type_base(), "https://errors.acme.example/types/");
    ///
    /// // No public URL: the RFC 9457 default, never someone else's domain.
    /// let v = Venture::new("acme", "acme.example").public_url("  ");
    /// assert_eq!(v.problem_type_base(), "about:blank");
    /// ```
    #[must_use]
    pub fn problem_type_base(&self) -> String {
        if let Some(base) = self
            .problem_base
            .as_deref()
            .map(str::trim)
            .filter(|base| !base.is_empty())
        {
            if base == crate::problem::ABOUT_BLANK {
                return base.to_owned();
            }
            // One trailing slash, so the slug is appended, not glued on.
            return format!("{}/", base.trim_end_matches('/'));
        }
        let public = self.public_url.trim();
        if public.is_empty() {
            return crate::problem::ABOUT_BLANK.to_owned();
        }
        format!("{}/problems/", public.trim_end_matches('/'))
    }

    #[must_use]
    pub fn cors_origins(mut self, origins: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.cors_origins = origins.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn env(mut self, env: VentureEnv) -> Self {
        self.env = env;
        self
    }

    /// Mail branding for templates (accent, logo, footer).
    #[must_use]
    pub fn brand(mut self, brand: Brand) -> Self {
        self.brand = brand;
        self
    }

    /// Appends every rule violation to `errors` (issue #2: collect all
    /// problems, report them together).
    pub(crate) fn validate(&self, errors: &mut ConfigError) {
        if self.name.is_empty() {
            errors.push("venture: name must not be empty");
        } else if !is_kebab_case(&self.name) {
            errors.push(format!(
                "venture: name `{}` must be kebab-case ([a-z0-9]+ separated by '-')",
                self.name
            ));
        }

        if self.domain.trim().is_empty() {
            errors.push("venture: domain must not be empty");
        }

        if self.cors_origins.is_empty() {
            errors.push(format!(
                "venture `{}`: at least one CORS origin is required",
                self.name
            ));
        } else {
            for origin in &self.cors_origins {
                if origin == "*" {
                    errors.push(format!(
                        "venture `{}`: wildcard CORS origin `*` is not allowed",
                        self.name
                    ));
                } else if !is_valid_origin(origin) {
                    errors.push(format!(
                        "venture `{}`: CORS origin `{origin}` must be scheme://host[:port] \
                         or a known browser-extension origin",
                        self.name
                    ));
                }
            }
        }
    }
}

fn is_kebab_case(name: &str) -> bool {
    !name.is_empty()
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

fn is_valid_origin(origin: &str) -> bool {
    // scheme://host[:port] with no path, query or fragment.
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if scheme.is_empty() {
        return false;
    }
    // A browser extension's origin carries a hyphen in the scheme, so the
    // alphanumeric-scheme rule below rejects it (issue #579). Admit exactly
    // three such schemes, as **exact-match origins only**: the id is checked
    // in full, so there is no wildcard, bare scheme, port, path or trailing
    // slash — the same shapes an `https` origin may not have. Any other
    // hyphenated scheme (`foo-bar://…`, `chrome-extensions://…`) still falls
    // through to the alphanumeric check and is rejected.
    match scheme {
        "chrome-extension" => return is_chrome_extension_id(rest),
        // Firefox emits lowercase ids.
        "moz-extension" => return is_extension_uuid(rest, false),
        // Safari emits uppercase ids; either case is accepted for this one
        // scheme (Firefox's stays lowercase-only, so the two are documented
        // distinct).
        "safari-web-extension" => return is_extension_uuid(rest, true),
        _ => {}
    }
    if !scheme.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if rest.contains(['/', '?', '#']) {
        return false;
    }
    let hostport = rest;
    let host = hostport.split_once(':').map_or(hostport, |(h, _)| h);
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
}

/// A Chrome extension id: exactly 32 characters, each `a`–`p` (digits and
/// letters above `p` never occur in a real id).
fn is_chrome_extension_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| ('a'..='p').contains(&c))
}

/// A canonical RFC 4122 UUID, `8-4-4-4-12` hex. `any_case` also admits
/// uppercase hex, which Safari emits and Firefox does not.
fn is_extension_uuid(id: &str, any_case: bool) -> bool {
    let bytes = id.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_hexdigit() && (any_case || !b.is_ascii_uppercase()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(v: &Venture) -> Vec<String> {
        let mut errs = ConfigError::default();
        v.validate(&mut errs);
        errs.problems
    }

    #[test]
    fn valid_venture_has_no_errors() {
        let v = Venture::new("factory0", "factory0.ventures")
            .cors_origins(["https://factory0.ventures"]);
        assert!(errors(&v).is_empty());
    }

    #[test]
    fn name_must_be_kebab_case() {
        let v = Venture::new("Factory0", "factory0.ventures")
            .cors_origins(["https://factory0.ventures"]);
        assert!(errors(&v).iter().any(|e| e.contains("kebab-case")));
    }

    #[test]
    fn domain_must_be_non_empty() {
        let v = Venture::new("factory0", " ").cors_origins(["https://x.dev"]);
        assert!(errors(&v).iter().any(|e| e.contains("domain")));
    }

    #[test]
    fn at_least_one_cors_origin() {
        let v = Venture::new("factory0", "factory0.ventures");
        assert!(errors(&v).iter().any(|e| e.contains("CORS origin")));
    }

    #[test]
    fn wildcard_origin_rejected() {
        let v = Venture::new("factory0", "factory0.ventures").cors_origins(["*"]);
        assert!(errors(&v).iter().any(|e| e.contains("wildcard")));
    }

    /// A single-origin venture is valid exactly when `is_valid_origin` passes
    /// (the other fields are always valid here).
    fn origin_is_valid(origin: &str) -> bool {
        errors(&Venture::new("factory0", "factory0.ventures").cors_origins([origin])).is_empty()
    }

    #[test]
    fn browser_extension_origins_are_accepted() {
        // Chrome: 32 characters, each a-p.
        assert!(origin_is_valid(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
        // Firefox emits a lowercase UUID.
        assert!(origin_is_valid(
            "moz-extension://5de6e0f6-2b1a-4f6e-9c3d-0a1b2c3d4e5f"
        ));
        // Safari emits uppercase; either case is accepted for this scheme.
        assert!(origin_is_valid(
            "safari-web-extension://5DE6E0F6-2B1A-4F6E-9C3D-0A1B2C3D4E5F"
        ));
        assert!(origin_is_valid(
            "safari-web-extension://5de6e0f6-2b1a-4f6e-9c3d-0a1b2c3d4e5f"
        ));
    }

    #[test]
    fn malformed_chrome_extension_ids_are_rejected() {
        // Short and long by one character.
        assert!(!origin_is_valid(
            "chrome-extension://abcdefghijklmnopabcdefghijklmno"
        ));
        assert!(!origin_is_valid(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnopq"
        ));
        // 'q' is past `p`; a digit and an uppercase letter are out of range.
        assert!(!origin_is_valid(
            "chrome-extension://qbcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!origin_is_valid(
            "chrome-extension://0bcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!origin_is_valid(
            "chrome-extension://Abcdefghijklmnopabcdefghijklmnop"
        ));
        // No bare scheme, port, path or trailing slash.
        assert!(!origin_is_valid("chrome-extension://"));
        assert!(!origin_is_valid(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop:80"
        ));
        assert!(!origin_is_valid(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/x"
        ));
        assert!(!origin_is_valid(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        ));
    }

    #[test]
    fn malformed_extension_uuids_are_rejected() {
        // Firefox ids are lowercase-only; the uppercase form is not accepted.
        assert!(!origin_is_valid(
            "moz-extension://5DE6E0F6-2B1A-4F6E-9C3D-0A1B2C3D4E5F"
        ));
        // No dashes at all.
        assert!(!origin_is_valid(
            "moz-extension://5de6e0f62b1a4f6e9c3d0a1b2c3d4e5f"
        ));
        // A group one character short.
        assert!(!origin_is_valid(
            "moz-extension://5de6e0f6-2b1a-4f6e-9c3d-0a1b2c3d4e5"
        ));
        // Non-hex trailing character.
        assert!(!origin_is_valid(
            "moz-extension://5de6e0f6-2b1a-4f6e-9c3d-0a1b2c3d4e5g"
        ));
        // No bare scheme, path or trailing slash.
        assert!(!origin_is_valid("moz-extension://"));
        assert!(!origin_is_valid("safari-web-extension://"));
        assert!(!origin_is_valid(
            "safari-web-extension://5de6e0f6-2b1a-4f6e-9c3d-0a1b2c3d4e5f/x"
        ));
        assert!(!origin_is_valid(
            "safari-web-extension://5de6e0f6-2b1a-4f6e-9c3d-0a1b2c3d4e5f/"
        ));
    }

    #[test]
    fn other_hyphenated_schemes_and_nulls_are_rejected() {
        // Any other hyphenated scheme, including a near-miss of a known one.
        assert!(!origin_is_valid("foo-bar://x"));
        assert!(!origin_is_valid(
            "chrome-extensions://abcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!origin_is_valid("null"));
        assert!(!origin_is_valid("*"));
        // `https` rules are unchanged: no path, port stays allowed.
        assert!(origin_is_valid("https://app.example:8443"));
        assert!(!origin_is_valid("https://app.example/"));
    }
}
