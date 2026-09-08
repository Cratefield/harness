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
}

/// The curated set of modules a venture may be built from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    pub modules: Vec<CatalogModule>,
}

/// A validated, resolved selection: the modules a venture will carry, in
/// an order where a module's dependencies come before it (build and mount
/// order). Core modules are always present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSet {
    ordered: Vec<String>,
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

    /// The content address of the set: the sorted slugs joined with `+`,
    /// so two selections with the same modules produce the same key
    /// whatever order they were picked in (harness ADR 0009 keys the
    /// artifact on the module set, not the customer).
    #[must_use]
    pub fn content_key(&self) -> String {
        let mut sorted: Vec<&str> = self.ordered.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.join("+")
    }
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
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::UnknownModule(slug) => {
                write!(f, "`{slug}` is not a module in the catalog")
            }
            ResolveError::Catalog(err) => write!(f, "the catalog is invalid: {err}"),
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
    /// module's dependencies come before it.
    ///
    /// # Errors
    ///
    /// [`ResolveError::UnknownModule`] for a selected slug the catalog
    /// does not have, or [`ResolveError::Catalog`] if the catalog is
    /// itself invalid.
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
        Ok(ModuleSet { ordered })
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

/// The built-in catalog: the harness modules that exist today, matching
/// control-plane's `curated()` slugs and tiers. Dependency edges are
/// added as modules gain them.
#[must_use]
pub fn builtin() -> Catalog {
    fn m(slug: &str, name: &str, summary: &str, tier: Tier, deps: &[&str]) -> CatalogModule {
        CatalogModule {
            slug: slug.to_owned(),
            name: name.to_owned(),
            summary: summary.to_owned(),
            tier,
            depends_on: deps.iter().map(|s| (*s).to_owned()).collect(),
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
