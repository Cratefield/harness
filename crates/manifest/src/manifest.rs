//! The venture manifest: the small, declarative document that says what a
//! backend *is* — which modules, on which host, with what config and seed
//! data. It is the unit an AI agent emits and the unit that promotes to
//! Cloudflare unchanged. Both engines consume the same struct: the native
//! compile engine (`fz build`) generates a venture crate from it; the wasm
//! compose engine (later) mounts the same module set in the browser.
//!
//! The manifest carries *intent* (a list of module slugs). Turning that
//! into an ordered, dependency-complete module set is [`Catalog::resolve`]
//! ([`crate::catalog`]); the manifest never encodes resolution results, so
//! two manifests naming the same modules always resolve identically.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::catalog::{Catalog, ModuleSet, ResolveError};

/// A reference to a module in a manifest: either a bare slug string, or an
/// object with per-module `config`. The two forms are interchangeable, so
/// `"waitlist"` and `{ "slug": "waitlist" }` mean the same thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ModuleRef {
    /// `"waitlist"`
    Slug(String),
    /// `{ "slug": "waitlist", "config": { "confirm_ttl_days": "7" } }`
    Detailed {
        slug: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        config: BTreeMap<String, String>,
    },
}

impl ModuleRef {
    /// The module slug, whichever form this reference took.
    #[must_use]
    pub fn slug(&self) -> &str {
        match self {
            ModuleRef::Slug(slug) | ModuleRef::Detailed { slug, .. } => slug,
        }
    }

    /// The per-module config, empty for the bare-slug form.
    #[must_use]
    pub fn config(&self) -> BTreeMap<String, String> {
        match self {
            ModuleRef::Slug(_) => BTreeMap::new(),
            ModuleRef::Detailed { config, .. } => config.clone(),
        }
    }
}

/// A venture, declared. Serialize/deserialize as JSON here; the CLI also
/// accepts TOML and converts it into this struct before calling in, so the
/// manifest crate itself stays serde-only and wasm-clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VentureManifest {
    /// The venture name. Becomes the generated crate name (kebab-case).
    pub name: String,
    /// The primary host the backend answers on, e.g. `acme.factory0.dev`.
    pub host: String,
    /// The canonical public URL, if it differs from `https://{host}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// First-party origins allowed to call the API from a browser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cors_origins: Vec<String>,
    /// The modules the venture carries, in any order. Dependencies are
    /// pulled in by resolution; the author lists only what they chose.
    pub modules: Vec<ModuleRef>,
    /// Venture-wide config keys (the `Config` port reads these).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, String>,
    /// SQL run once after migrations, to seed rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_sql: Option<String>,
}

/// Why a manifest is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The `name` or `host` field is empty.
    MissingField(&'static str),
    /// The same module slug is listed more than once.
    DuplicateModule(String),
    /// Resolution against the catalog failed.
    Resolve(ResolveError),
    /// The document did not parse as a manifest.
    Parse(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::MissingField(field) => write!(f, "manifest `{field}` must not be empty"),
            ManifestError::DuplicateModule(slug) => {
                write!(f, "module `{slug}` is listed more than once")
            }
            ManifestError::Resolve(err) => write!(f, "{err}"),
            ManifestError::Parse(msg) => write!(f, "could not parse manifest: {msg}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl VentureManifest {
    /// Parse a manifest from JSON.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Parse`] if the JSON is not a valid manifest.
    pub fn from_json_str(json: &str) -> Result<Self, ManifestError> {
        serde_json::from_str(json).map_err(|err| ManifestError::Parse(err.to_string()))
    }

    /// Serialize the manifest to pretty JSON.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Parse`] if serialization fails (it should not).
    pub fn to_json_string(&self) -> Result<String, ManifestError> {
        serde_json::to_string_pretty(self).map_err(|err| ManifestError::Parse(err.to_string()))
    }

    /// The module slugs the author selected, in listed order.
    #[must_use]
    pub fn module_slugs(&self) -> Vec<&str> {
        self.modules.iter().map(ModuleRef::slug).collect()
    }

    /// Check the manifest is well-formed on its own terms: `name` and
    /// `host` present, no duplicate modules. Resolution against a catalog
    /// is [`Self::resolve`].
    ///
    /// # Errors
    ///
    /// The first structural problem found.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.name.trim().is_empty() {
            return Err(ManifestError::MissingField("name"));
        }
        if self.host.trim().is_empty() {
            return Err(ManifestError::MissingField("host"));
        }
        let mut seen = std::collections::HashSet::new();
        for slug in self.module_slugs() {
            if !seen.insert(slug) {
                return Err(ManifestError::DuplicateModule(slug.to_owned()));
            }
        }
        Ok(())
    }

    /// Validate, then resolve the selected modules against `catalog` into
    /// the ordered, dependency-complete module set that keys the artifact.
    ///
    /// # Errors
    ///
    /// A structural [`ManifestError`], or [`ManifestError::Resolve`] if a
    /// selected module is unknown or the catalog is invalid.
    pub fn resolve(&self, catalog: &Catalog) -> Result<ModuleSet, ManifestError> {
        self.validate()?;
        catalog
            .resolve(&self.module_slugs())
            .map_err(ManifestError::Resolve)
    }
}
