//! The module catalog and dependency resolution (issue #5).
//!
//! A curated list of the modules a customer may put in a venture, each
//! with a tier — `core`, always included, or `optional` — and its
//! dependencies. Two things happen here and nowhere else:
//!
//! - **Resolution.** Selecting a module pulls its dependency closure;
//!   the result is the *module set* that keys the artifact (harness ADR
//!   0009) and drives provisioning.
//! - **Deselection.** Removing a module that another still needs is
//!   refused, with the reason, so the wizard can grey out a checkbox
//!   instead of producing a broken set.
//!
//! The catalog is **data the control plane owns**, not a scan of a
//! registry: a module is here because someone wrote its customer-facing
//! description and set its tier. A cyclic or dangling dependency is a
//! catalog error caught by [`Catalog::validate`] before it ships, never
//! a customer's problem at pick time.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet};

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

/// One catalog entry.
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

/// The curated set of modules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    pub modules: Vec<CatalogModule>,
}

/// A validated, resolved selection: the modules a venture will carry, in
/// an order where a module's dependencies come before it (build and
/// mount order). Core modules are always present.
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

    /// The content address of the set: the sorted slugs joined, so two
    /// selections with the same modules produce the same key whatever
    /// order they were picked in (harness ADR 0009 keys the artifact on
    /// the module set, not the customer).
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

impl Catalog {
    /// Checks the catalog is coherent: no duplicates, no dangling or
    /// cyclic dependencies, no core module depending on an optional one.
    /// Run in a test so a bad edit fails CI, not a customer.
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

        // Roots: every core module, plus the selection.
        let mut roots: Vec<&str> = self
            .modules
            .iter()
            .filter(|m| m.tier == Tier::Core)
            .map(|m| m.slug.as_str())
            .collect();
        roots.extend(selected.iter().copied());

        // Depth-first postorder over the dependency edges gives an order
        // where dependencies precede dependants; a visited set makes the
        // closure and dedups.
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
    /// The `Err` names the module that needs it (or that it is core), so
    /// the wizard can say why the checkbox is greyed out.
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
    // Grey/black DFS: a back-edge to a grey node is a cycle.
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
                        // The cycle is the stack from `dep` onward.
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
            // `by_slug` has the real key; find it so lifetimes line up.
            if let Some((key, _)) = by_slug.get_key_value(dep.as_str()) {
                visit(key, by_slug, visited, ordered);
            }
        }
    }
    ordered.push(slug.to_owned());
}

/// The curated catalog the control plane ships with. Seeded with the
/// harness modules that exist today; dependency edges are added as
/// modules gain them (harness#26, `depends_on`). The resolution engine
/// is exercised against richer synthetic catalogs in the tests.
#[must_use]
pub fn curated() -> Catalog {
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

/// The set of slugs the curated catalog offers, for a quick membership
/// check without building the whole catalog.
#[must_use]
pub fn curated_slugs() -> BTreeSet<String> {
    curated().modules.into_iter().map(|m| m.slug).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic catalog with real edges, for exercising resolution:
    /// `blog` needs `accounts`; `comments` needs `blog` and `accounts`;
    /// `base` is core; `standalone` needs nothing.
    fn rich() -> Catalog {
        fn m(slug: &str, tier: Tier, deps: &[&str]) -> CatalogModule {
            CatalogModule {
                slug: slug.to_owned(),
                name: slug.to_owned(),
                summary: String::new(),
                tier,
                depends_on: deps.iter().map(|s| (*s).to_owned()).collect(),
            }
        }
        Catalog {
            modules: vec![
                m("base", Tier::Core, &[]),
                m("accounts", Tier::Optional, &[]),
                m("blog", Tier::Optional, &["accounts"]),
                m("comments", Tier::Optional, &["blog", "accounts"]),
                m("standalone", Tier::Optional, &[]),
            ],
        }
    }

    #[test]
    fn the_curated_catalog_is_valid() {
        curated()
            .validate()
            .expect("the shipped catalog must be coherent");
    }

    #[test]
    fn resolving_pulls_the_dependency_closure_in_order() {
        let set = rich().resolve(&["comments"]).expect("resolves");
        // base (core) is always in; comments pulls blog and accounts.
        assert!(set.contains("base"));
        assert!(set.contains("comments"));
        assert!(set.contains("blog"));
        assert!(set.contains("accounts"));
        assert!(!set.contains("standalone"), "not selected, not pulled");
        // dependencies precede dependants
        let pos = |s: &str| set.slugs().iter().position(|x| x == s).unwrap();
        assert!(pos("accounts") < pos("blog"));
        assert!(pos("blog") < pos("comments"));
    }

    #[test]
    fn core_is_always_present_even_with_an_empty_selection() {
        let set = rich().resolve(&[]).expect("resolves");
        assert_eq!(set.slugs(), &["base"]);
    }

    #[test]
    fn the_content_key_is_order_independent() {
        let a = rich().resolve(&["blog", "standalone"]).expect("resolves");
        let b = rich().resolve(&["standalone", "blog"]).expect("resolves");
        assert_eq!(a.content_key(), b.content_key());
        // and it names the modules, sorted
        assert_eq!(a.content_key(), "accounts+base+blog+standalone");
    }

    #[test]
    fn an_unknown_selection_is_refused() {
        let err = rich().resolve(&["nope"]).expect_err("unknown module");
        assert_eq!(err, ResolveError::UnknownModule("nope".to_owned()));
    }

    #[test]
    fn a_needed_module_cannot_be_deselected_and_the_reason_names_who_needs_it() {
        let catalog = rich();
        let set = catalog.resolve(&["comments"]).expect("resolves");
        // accounts is needed by blog and comments.
        let err = catalog.can_deselect(&set, "accounts").expect_err("needed");
        assert!(err.contains("needed by"), "{err}");
        assert!(err.contains("blog") && err.contains("comments"), "{err}");
        // core cannot be removed.
        let err = catalog.can_deselect(&set, "base").expect_err("core");
        assert!(err.contains("core module"), "{err}");
        // a leaf can.
        catalog
            .can_deselect(&set, "comments")
            .expect("nothing needs comments");
    }

    #[test]
    fn a_cycle_is_a_catalog_error_not_a_resolve_time_surprise() {
        let mut catalog = rich();
        // make accounts depend on comments -> accounts->...->comments->accounts
        catalog
            .modules
            .iter_mut()
            .find(|m| m.slug == "accounts")
            .unwrap()
            .depends_on
            .push("comments".to_owned());
        match catalog.validate() {
            Err(CatalogError::Cycle(members)) => {
                for slug in ["accounts", "blog", "comments"] {
                    assert!(members.contains(&slug.to_owned()), "{members:?}");
                }
            }
            other => panic!("expected a cycle, got {other:?}"),
        }
        // and resolve surfaces it rather than looping
        assert!(matches!(
            catalog.resolve(&["blog"]),
            Err(ResolveError::Catalog(CatalogError::Cycle(_)))
        ));
    }

    #[test]
    fn a_dangling_dependency_is_caught() {
        let mut catalog = rich();
        catalog
            .modules
            .iter_mut()
            .find(|m| m.slug == "blog")
            .unwrap()
            .depends_on
            .push("ghost".to_owned());
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::DanglingDependency { .. })
        ));
    }

    #[test]
    fn a_core_module_may_not_depend_on_an_optional_one() {
        let mut catalog = rich();
        catalog
            .modules
            .iter_mut()
            .find(|m| m.slug == "base")
            .unwrap()
            .depends_on
            .push("accounts".to_owned());
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::CoreDependsOnOptional { .. })
        ));
    }

    #[test]
    fn the_catalog_round_trips_through_json() {
        let json = serde_json::to_string(&curated()).expect("serialize");
        let back: Catalog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.modules.len(), curated().modules.len());
    }
}
