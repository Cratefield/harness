//! The module catalog and dependency resolution.
//!
//! This is the canonical, wasm-clean home of the resolution engine that
//! control-plane's `cratefield_catalog` currently carries a copy of
//! (issue #5). The two are kept **semantically identical** on purpose —
//! same postorder-DFS ordering, same `content_key` (sorted slugs joined
//! with `+`, harness ADR 0009), same unknown/cycle/dangling errors — so
//! control-plane can later depend on this crate and delete its copy. The
//! manifest ([`crate::VentureManifest`]) is the serializable front-end to
//! this resolver; it does not fork the logic.
//!
//! ## What may be selected (issue #142)
//!
//! A catalog entry is **data, not a security boundary**: a `Port`
//! declaration is not a sandbox, and in-process modules are not a
//! sandbox, so the non-coder tier must never be able to pull an
//! unreviewed or drifting build out of a compile. Selection is therefore
//! gated on [`ModuleRelease`] rows: an entry resolves only when it
//! carries at least one **pinned** release — an exact version plus a
//! content digest — that is **reviewed** (approved), and a release that
//! has been **revoked** is refused even when an existing manifest
//! already referenced it. Unpinned, unreviewed and revoked are hard
//! refusals ([`ResolveError`]), never warnings. Revoking an unsafe
//! release makes every future resolution that needs it fail, which is
//! the supportable half of the story: what the build *service* owes the
//! pin (fetch-by-digest, isolated construction) is the
//! `BuildEnvironmentAttestation` contract in [`crate::provenance`], and
//! the registry-side revocation feed is infrastructure (see the issue's
//! scope notes).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Whether a module is always in every venture or a customer choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Always included; cannot be deselected.
    Core,
    /// The customer picks it.
    Optional,
}

/// The review state of one release (issue #142). A release is only
/// selectable while it is [`ReleaseReview::Approved`]; approval is a
/// human decision recorded here so it can be audited and, crucially,
/// reversed: [`ReleaseReview::Revoked`] is the state an unsafe release
/// is moved into, and resolution refuses it by name and reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseReview {
    /// Cut but not reviewed yet. Never selectable.
    Pending,
    /// Reviewed and approved for selection by the named reviewer.
    Approved {
        reviewer: String,
        reviewed_at: String,
    },
    /// Withdrawn as unsafe. Every resolution that would pick this
    /// release fails, naming the reason, even for a manifest that
    /// referenced it before revocation (issue #142).
    Revoked {
        by: String,
        revoked_at: String,
        reason: String,
    },
}

/// One pinned module release: an exact version and a content digest,
/// under a [`ReleaseReview`]. `version` must be an exact number
/// (`N.N.N`, no ranges, no pre-release tags) and `digest` a
/// `sha256:<64 hex>` content address — anything else is not a pin and
/// resolution will not build from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRelease {
    /// Exact version, e.g. `"0.1.1"`. A range (`^0.1`) is not a pin.
    pub version: String,
    /// Content digest of the release artifact, `sha256:<64 hex>`.
    pub digest: String,
    pub review: ReleaseReview,
}

impl ModuleRelease {
    /// Whether this release is **pinned**: an exact `N.N.N` version
    /// paired with a well-formed `sha256:` content digest. Both halves
    /// are required — a version without a digest is a drifting tag.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        is_exact_version(&self.version) && is_sha256_digest(&self.digest)
    }

    /// Whether a human has approved this release for selection.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self.review, ReleaseReview::Approved { .. })
    }

    /// Whether this release has been revoked as unsafe (issue #142).
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self.review, ReleaseReview::Revoked { .. })
    }
}

/// The release [`ModuleSet`] resolution actually selected for one slug:
/// the pin the build must fetch and the provenance must record
/// (issue #142).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedRelease {
    pub slug: String,
    pub version: String,
    pub digest: String,
}

/// One catalog entry: a module a venture may carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogModule {
    /// Stable, kebab-case; the harness module name and the key everywhere.
    pub slug: String,
    /// Shown in the wizard.
    pub name: String,
    /// One line, written for a customer rather than a compiler.
    pub summary: String,
    pub tier: Tier,
    /// Slugs this module needs. Pulled in when it is selected; ordered
    /// before it in a resolved set.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// The reviewed, pinned releases this entry offers (issue #142),
    /// newest first. Resolution takes the first usable one; an entry
    /// with none selectable is refused, not warned about.
    #[serde(default)]
    pub releases: Vec<ModuleRelease>,
}

/// The curated set of modules a venture may be built from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    pub modules: Vec<CatalogModule>,
}

/// A validated, resolved selection: the modules a venture will carry, in
/// an order where a module's dependencies come before it (build and mount
/// order), each pinned to the exact reviewed release resolution picked
/// (issue #142). Core modules are always present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSet {
    ordered: Vec<String>,
    releases: Vec<PinnedRelease>,
}

impl ModuleSet {
    /// The slugs, dependencies before dependants.
    #[must_use]
    pub fn slugs(&self) -> &[String] {
        &self.ordered
    }

    /// Whether a slug is in the set.
    #[must_use]
    pub fn contains(&self, slug: &str) -> bool {
        self.ordered.iter().any(|s| s == slug)
    }

    /// The exact reviewed releases the resolution pinned, in slug order
    /// of [`Self::slugs`] (issue #142). Provenance records these, so a
    /// built artifact says what it was built from.
    #[must_use]
    pub fn releases(&self) -> &[PinnedRelease] {
        &self.releases
    }

    /// The pin chosen for one slug, if it is in the set.
    #[must_use]
    pub fn release(&self, slug: &str) -> Option<&PinnedRelease> {
        self.releases.iter().find(|r| r.slug == slug)
    }

    /// The content address of the set: the sorted slugs joined with `+`,
    /// so two selections with the same modules produce the same key
    /// whatever order they were picked in (harness ADR 0009 keys the
    /// artifact on the module set, not the customer). The pinned
    /// versions are deliberately *not* in this key: it names the set,
    /// [`Self::releases`] names the exact builds, and provenance binds
    /// the two.
    #[must_use]
    pub fn content_key(&self) -> String {
        let mut sorted: Vec<&str> = self.ordered.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.join("+")
    }
}

/// Whether `version` is an exact `N.N.N` pin (issue #142): digits only,
/// no ranges, no wildcards, no pre-release tags. A non-coder build must
/// be reconstructible from the number alone.
#[must_use]
pub fn is_exact_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Whether `digest` is a `sha256:<64 lowercase hex>` content address
/// (issue #142).
#[must_use]
pub fn is_sha256_digest(digest: &str) -> bool {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Why a catalog will not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    /// The same slug appears twice.
    Duplicate(String),
    /// A module depends on a slug the catalog does not contain.
    DanglingDependency { module: String, missing: String },
    /// A dependency cycle; the slugs are the members, sorted.
    Cycle(Vec<String>),
    /// A core module depends on an optional one, which would make the
    /// optional one un-removable and therefore not optional.
    CoreDependsOnOptional { core: String, optional: String },
    /// A release row carries a digest that is not a `sha256:<64 hex>`
    /// content address (issue #142). Malformed pins are a data bug, so
    /// `validate` fails on them the way it fails on a dangling
    /// dependency; a *well-formed but unreviewed or revoked* pin is a
    /// policy state, and refuses at resolve time instead.
    BadDigest { slug: String, digest: String },
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogError::Duplicate(slug) => write!(f, "module `{slug}` is listed twice"),
            CatalogError::DanglingDependency { module, missing } => write!(
                f,
                "module `{module}` depends on `{missing}`, which is not in the catalog"
            ),
            CatalogError::Cycle(members) => {
                write!(f, "dependency cycle among {}", members.join(", "))
            }
            CatalogError::CoreDependsOnOptional { core, optional } => write!(
                f,
                "core module `{core}` depends on optional module `{optional}`, which would make \
                 `{optional}` un-removable and so not optional"
            ),
            CatalogError::BadDigest { slug, digest } => write!(
                f,
                "module `{slug}` carries a release digest `{digest}` that is not a \
                 `sha256:<64 hex>` content address"
            ),
        }
    }
}

impl std::error::Error for CatalogError {}

/// Why a selection will not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// A selected slug is not in the catalog.
    UnknownModule(String),
    /// The catalog itself is broken; fix it before anyone selects.
    Catalog(CatalogError),
    /// The entry carries no release pinned to an exact version and a
    /// content digest (issue #142). The non-coder tier never floats:
    /// refusal, not a warning.
    Unpinned(String),
    /// The entry's pinned releases exist but none is approved (issue
    /// #142). `version` names the newest pinned-but-unreviewed release.
    Unreviewed { slug: String, version: String },
    /// Resolution would have to build from a release revoked as unsafe
    /// (issue #142). This fires even when the requesting manifest
    /// referenced the release before it was revoked: revocation is
    /// forward-effective at every resolution and build.
    Revoked {
        slug: String,
        version: String,
        reason: String,
    },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::UnknownModule(slug) => {
                write!(f, "`{slug}` is not a module in the catalog")
            }
            ResolveError::Catalog(err) => write!(f, "the catalog is invalid: {err}"),
            ResolveError::Unpinned(slug) => write!(
                f,
                "`{slug}` has no pinned release (an exact version plus a `sha256:` digest); \
                 the non-coder tier does not build from floating or unpublished versions"
            ),
            ResolveError::Unreviewed { slug, version } => write!(
                f,
                "`{slug}` release `{version}` is pinned but not reviewed; only reviewed \
                 releases may be selected"
            ),
            ResolveError::Revoked {
                slug,
                version,
                reason,
            } => write!(
                f,
                "`{slug}` release `{version}` was revoked as unsafe: {reason}. Resolve refuses \
                 it even though the manifest referenced it; wait for a reviewed replacement."
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

impl Catalog {
    /// Checks the catalog is coherent: no duplicates, no dangling or
    /// cyclic dependencies, no core module depending on an optional one.
    ///
    /// # Errors
    ///
    /// The first problem found; fix it and re-run to find the next.
    pub fn validate(&self) -> Result<(), CatalogError> {
        let mut seen: HashSet<&str> = HashSet::new();
        for module in &self.modules {
            if !seen.insert(&module.slug) {
                return Err(CatalogError::Duplicate(module.slug.clone()));
            }
            for release in &module.releases {
                if !is_sha256_digest(&release.digest) {
                    return Err(CatalogError::BadDigest {
                        slug: module.slug.clone(),
                        digest: release.digest.clone(),
                    });
                }
            }
        }
        let by_slug = self.by_slug();
        for module in &self.modules {
            for dep in &module.depends_on {
                let Some(target) = by_slug.get(dep.as_str()) else {
                    return Err(CatalogError::DanglingDependency {
                        module: module.slug.clone(),
                        missing: dep.clone(),
                    });
                };
                if module.tier == Tier::Core && target.tier == Tier::Optional {
                    return Err(CatalogError::CoreDependsOnOptional {
                        core: module.slug.clone(),
                        optional: dep.clone(),
                    });
                }
            }
        }
        if let Some(cycle) = find_cycle(&by_slug) {
            return Err(CatalogError::Cycle(cycle));
        }
        Ok(())
    }

    /// The module set for a selection: every core module, the selected
    /// optional ones, and the dependency closure of both, ordered so a
    /// module's dependencies come before it. Every member must resolve
    /// to a reviewed, pinned release or the selection is refused
    /// (issue #142) — the closure gets no trust exemption.
    ///
    /// # Errors
    ///
    /// [`ResolveError::UnknownModule`] for a selected slug the catalog
    /// does not have, [`ResolveError::Catalog`] if the catalog is
    /// itself invalid, or [`ResolveError::Unpinned`] /
    /// [`ResolveError::Unreviewed`] / [`ResolveError::Revoked`] naming
    /// the first closure member with no usable release (issue #142).
    ///
    /// # Panics
    ///
    /// Never: every slug pinned in the loop was collected from the same
    /// `by_slug` map a line above, so the lookup cannot miss.
    pub fn resolve(&self, selected: &[&str]) -> Result<ModuleSet, ResolveError> {
        self.validate().map_err(ResolveError::Catalog)?;
        let by_slug = self.by_slug();
        for slug in selected {
            if !by_slug.contains_key(slug) {
                return Err(ResolveError::UnknownModule((*slug).to_owned()));
            }
        }

        let mut roots: Vec<&str> = self
            .modules
            .iter()
            .filter(|m| m.tier == Tier::Core)
            .map(|m| m.slug.as_str())
            .collect();
        roots.extend(selected.iter().copied());

        let mut ordered: Vec<String> = Vec::new();
        let mut visited: HashSet<&str> = HashSet::new();
        for root in roots {
            visit(root, &by_slug, &mut visited, &mut ordered);
        }
        // Every module in the closure — selected, core, or pulled in as
        // a dependency — must offer a reviewed, pinned release
        // (issue #142). The dependency graph is not a trust exemption:
        // a blog that depends on an unreviewed `accounts` fails for
        // `accounts`, not quietly.
        let mut releases: Vec<PinnedRelease> = Vec::with_capacity(ordered.len());
        for slug in &ordered {
            let module = by_slug
                .get(slug.as_str())
                .expect("ordered slugs come from by_slug");
            releases.push(pin(module)?);
        }
        Ok(ModuleSet { ordered, releases })
    }

    /// Whether `slug` can be removed from a resolved set: no, if it is a
    /// core module, or if another module in the set still depends on it.
    ///
    /// # Errors
    ///
    /// A human-readable reason it cannot be removed.
    pub fn can_deselect(&self, set: &ModuleSet, slug: &str) -> Result<(), String> {
        let by_slug = self.by_slug();
        if let Some(module) = by_slug.get(slug)
            && module.tier == Tier::Core
        {
            return Err(format!("`{slug}` is a core module and is always included"));
        }
        let needed_by: Vec<&str> = set
            .ordered
            .iter()
            .filter(|other| other.as_str() != slug)
            .filter(|other| {
                by_slug
                    .get(other.as_str())
                    .is_some_and(|m| m.depends_on.iter().any(|d| d == slug))
            })
            .map(String::as_str)
            .collect();
        if needed_by.is_empty() {
            Ok(())
        } else {
            Err(format!("`{slug}` is needed by {}", needed_by.join(", ")))
        }
    }

    fn by_slug(&self) -> HashMap<&str, &CatalogModule> {
        self.modules.iter().map(|m| (m.slug.as_str(), m)).collect()
    }
}

/// The members of a dependency cycle, if any, as a sorted list.
fn find_cycle(by_slug: &HashMap<&str, &CatalogModule>) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Grey,
        Black,
    }
    fn dfs<'a>(
        slug: &'a str,
        by_slug: &HashMap<&'a str, &'a CatalogModule>,
        mark: &mut HashMap<&'a str, Mark>,
        stack: &mut Vec<&'a str>,
    ) -> Option<Vec<String>> {
        mark.insert(slug, Mark::Grey);
        stack.push(slug);
        if let Some(module) = by_slug.get(slug) {
            for dep in &module.depends_on {
                let dep = dep.as_str();
                match mark.get(dep) {
                    Some(Mark::Grey) => {
                        let start = stack.iter().position(|s| *s == dep).unwrap_or(0);
                        let mut members: Vec<String> =
                            stack[start..].iter().map(|s| (*s).to_owned()).collect();
                        members.sort();
                        members.dedup();
                        return Some(members);
                    }
                    Some(Mark::Black) => {}
                    None => {
                        if let Some(cycle) = dfs(dep, by_slug, mark, stack) {
                            return Some(cycle);
                        }
                    }
                }
            }
        }
        stack.pop();
        mark.insert(slug, Mark::Black);
        None
    }
    let mut mark: HashMap<&str, Mark> = HashMap::new();
    let mut keys: Vec<&str> = by_slug.keys().copied().collect();
    keys.sort_unstable();
    for slug in keys {
        if !mark.contains_key(slug) {
            let mut stack = Vec::new();
            if let Some(cycle) = dfs(slug, by_slug, &mut mark, &mut stack) {
                return Some(cycle);
            }
        }
    }
    None
}

/// Postorder DFS: append a node after its dependencies.
fn visit<'a>(
    slug: &'a str,
    by_slug: &HashMap<&'a str, &'a CatalogModule>,
    visited: &mut HashSet<&'a str>,
    ordered: &mut Vec<String>,
) {
    if visited.contains(slug) {
        return;
    }
    visited.insert(slug);
    if let Some(module) = by_slug.get(slug) {
        for dep in &module.depends_on {
            if let Some((key, _)) = by_slug.get_key_value(dep.as_str()) {
                visit(key, by_slug, visited, ordered);
            }
        }
    }
    ordered.push(slug.to_owned());
}

/// The release resolution will build `module` from, or the refusal
/// (issue #142). Releases are consulted in listed order (newest first);
/// the first one that is both fully pinned and approved wins. With no
/// winner, the refusal names the sharpest reason available: a revoked
/// release outranks an unreviewed one outranks a missing pin, because
/// revocation means somebody withdrew this exact build as unsafe and a
/// stale manifest must see that, not a generic "no releases".
fn pin(module: &CatalogModule) -> Result<PinnedRelease, ResolveError> {
    let slug = module.slug.clone();
    let mut revoked: Option<(&ModuleRelease, String)> = None;
    let mut unreviewed: Option<&ModuleRelease> = None;
    for release in &module.releases {
        if !release.is_pinned() {
            continue;
        }
        match &release.review {
            ReleaseReview::Approved { .. } => {
                return Ok(PinnedRelease {
                    slug,
                    version: release.version.clone(),
                    digest: release.digest.clone(),
                });
            }
            ReleaseReview::Revoked { reason, .. } => {
                if revoked.is_none() {
                    revoked = Some((release, reason.clone()));
                }
            }
            ReleaseReview::Pending => {
                if unreviewed.is_none() {
                    unreviewed = Some(release);
                }
            }
        }
    }
    if let Some((release, reason)) = revoked {
        return Err(ResolveError::Revoked {
            slug,
            version: release.version.clone(),
            reason,
        });
    }
    if let Some(release) = unreviewed {
        return Err(ResolveError::Unreviewed {
            slug,
            version: release.version.clone(),
        });
    }
    Err(ResolveError::Unpinned(slug))
}

/// The built-in catalog: the harness modules that exist today, matching
/// control-plane's `curated()` slugs, tiers and pins. Dependency edges
/// are added as modules gain them.
///
/// Each entry carries one reviewed release pinned to the current crate
/// version. The seed digests are the all-zero `sha256:` value on purpose
/// and visibly so: a digest is stamped when CI cuts a release from the
/// built artifact (control-plane infrastructure, out of this repo), and a
/// placeholder nobody can mistake for a real one beats a fabricated one
/// that would pass every format check while meaning nothing (issue #142
/// honesty rule). Resolution gates on review state and pin *shape*; the
/// build service must additionally refuse any pin whose digest is the
/// zero placeholder until release stamping lands — see
/// [`crate::provenance`].
#[must_use]
pub fn builtin() -> Catalog {
    fn m(slug: &str, name: &str, summary: &str, tier: Tier, deps: &[&str]) -> CatalogModule {
        CatalogModule {
            slug: slug.to_owned(),
            name: name.to_owned(),
            summary: summary.to_owned(),
            tier,
            depends_on: deps.iter().map(|s| (*s).to_owned()).collect(),
            releases: vec![ModuleRelease {
                version: "0.1.1".to_owned(),
                digest: format!("sha256:{}", "0".repeat(64)),
                review: ReleaseReview::Approved {
                    reviewer: "release-review".to_owned(),
                    reviewed_at: "2026-09-01T00:00:00Z".to_owned(),
                },
            }],
        }
    }
    Catalog {
        modules: vec![
            m(
                "email-signup",
                "Email signup",
                "Collect email addresses with double opt-in, confirmation and unsubscribe.",
                Tier::Optional,
                &[],
            ),
            m(
                "waitlist",
                "Waitlist",
                "A per-product waitlist with confirmation, positions and referral codes.",
                Tier::Optional,
                &[],
            ),
            m(
                "cms",
                "Content",
                "Typed, versioned content in your own database, edited through the admin.",
                Tier::Optional,
                &[],
            ),
        ],
    }
}
