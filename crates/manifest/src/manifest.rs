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

use cratefield_tables::Schema;

use crate::access::AccessMap;
use crate::privacy::TablePrivacyMap;

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
///
/// `PartialEq` but not `Eq`: a declared `real` field carries `f64`
/// bounds, and a float has no total equality. Nothing keyed a manifest by
/// value, so the bound was never load-bearing — it was available because
/// nothing in the struct had needed a float before.
///
/// `Default` so a caller building one in code can write the fields it
/// means and `..Default::default()` for the rest. Two call sites in the
/// CLI have now been broken twice by a new field, which is a cost the
/// struct was imposing rather than one they were choosing.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
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
    /// Tables the venture declares itself (issue #153), rather than
    /// getting from a module.
    ///
    /// Carried and checked here; **not yet generated from**. A manifest
    /// that declares tables is refused by `generate`, with the reason,
    /// rather than producing a venture whose tables quietly do not exist
    /// — see `GenerateError::TablesNotGenerated`.
    #[serde(default, skip_serializing_if = "Schema::is_empty")]
    pub tables: Schema,
    /// What each declared table holds, keyed by table name.
    ///
    /// Required for every declared table and checked by [`validate`]:
    /// there is no default, because both available defaults are wrong.
    /// See [`crate::privacy`].
    ///
    /// It lives here rather than on `TableDef` because a `TableDef` is
    /// also what `cratefield-introspect` builds from a live catalog, and
    /// a table read out of a database has no author to have declared
    /// anything — requiring it there would force that crate to invent
    /// one.
    ///
    /// [`validate`]: VentureManifest::validate
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub table_privacy: TablePrivacyMap,
    /// Who may reach each declared table, keyed by table name.
    ///
    /// Required for every declared table, with no default, for the
    /// reason `table_privacy` has one: `public-read` by default
    /// publishes a venture's tables the day the CRUD layer lands, and
    /// `admin` by default makes them useless until somebody notices.
    /// See [`crate::access`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub table_access: AccessMap,
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
    /// The `[tables]` declaration is not legal. Every problem at once,
    /// the way `Schema::validate` reports them.
    Tables(Vec<String>),
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
            ManifestError::Tables(problems) => {
                write!(f, "the [tables] declaration is not usable:")?;
                for problem in problems {
                    write!(f, "\n  - {problem}")?;
                }
                Ok(())
            }
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
        // The harness refuses a venture with no CORS origin
        // (`Venture::validate`), and a generated venture composes with
        // `.expect("generated venture harness is valid")` — so without
        // this the manifest builds happily and the venture panics on its
        // first request. Found by composing a generated venture, which
        // nothing did until `examples/tables-canary`.
        if self.cors_origins.is_empty() {
            return Err(ManifestError::MissingField("cors_origins"));
        }
        let mut seen = std::collections::HashSet::new();
        for slug in self.module_slugs() {
            if !seen.insert(slug) {
                return Err(ManifestError::DuplicateModule(slug.to_owned()));
            }
        }
        // Checked here so a malformed declaration is a manifest error,
        // reported next to the rest of the manifest's own, rather than
        // something the author meets later from a different layer.
        if let Err(errors) = self.tables.validate() {
            return Err(ManifestError::Tables(errors.problems));
        }
        // A declared table that does not say what it holds is outside
        // export, outside subject access and outside erasure — silently,
        // which is the shape of the hole this refuses to leave open.
        let mut problems = Vec::new();
        crate::privacy::validate(&self.tables, &self.table_privacy, &mut problems);
        crate::access::validate(
            &self.tables,
            &self.table_access,
            &self.table_privacy,
            &mut problems,
        );
        if !problems.is_empty() {
            return Err(ManifestError::Tables(problems));
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
