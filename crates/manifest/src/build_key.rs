//! The artifact's content address (issue #59): the build key a cache
//! would store and look a compiled venture up by.
//!
//! A managed deployment should not compile per customer. The artifact is
//! a pure function of the module set and their exact versions, the
//! harness API, the rustc that compiles it and the profile it compiles
//! under — so that tuple names the artifact, and two customers who pick
//! the same module set share it. One wasm can serve customers with and
//! without sidecar mounts precisely because the mount table is runtime
//! configuration ([`crate::provenance`]'s `HARNESS_SIDECARS`), never an
//! input to this key: two compositions differing only in their sidecar
//! mounts produce the same key, which is the amended acceptance
//! criterion of #59 and the property that makes the cache real.
//!
//! Ordering independence is the other load-bearing property: a manifest
//! lists modules in any order and resolution topologically sorts them,
//! but the key must not depend on even that resolved order, so the
//! inputs are sorted by slug before hashing.
//!
//! What the cache *does* with the key — where artifacts physically
//! live, the hit path — is a control-plane decision and out of scope
//! here (issue #59). This module is the identity half: it makes the
//! address computable, stable and inspectable from `fz build-key`.

use crate::catalog::PinnedRelease;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The build profile the artifact is compiled under. The venture's
/// `worker-build --release` step is the only profile any deploy path
/// invokes today; when a second profile ever exists, it becomes an
/// input a caller supplies rather than a constant this module hides.
pub const BUILD_PROFILE: &str = "release";

/// Everything the compiled artifact is a function of. Every field is an
/// equality: change any one and the key must change, because the bytes
/// it names could change. Deliberately *absent*: the venture name, the
/// host, config, seed data and the sidecar mount table — those are
/// per-customer deployment configuration, not artifact content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BuildKeyInputs {
    /// The exact reviewed releases resolution pinned, one per module.
    /// Order carries no meaning here; [`build_key`] sorts by slug.
    pub releases: Vec<PinnedRelease>,
    /// The harness API version the artifact is compiled against
    /// (`cratefield_core::HARNESS_API`). A module compiled against a
    /// different harness contract is a different artifact.
    pub harness_api: u32,
    /// The rustc version string (`rustc --version`). The wasm output is
    /// a function of the compiler; two rustc versions may legitimately
    /// produce different bytes.
    pub rustc_version: String,
    /// The build profile ([`BUILD_PROFILE`]).
    pub profile: String,
}

/// Why a build key cannot be computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildKeyError {
    /// The same slug appears twice in the releases. Resolution already
    /// refuses duplicates upstream, so reaching here means the caller
    /// bypassed it; keying on an ambiguous set would name two
    /// artifacts with one address.
    Duplicate(String),
}

impl std::fmt::Display for BuildKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildKeyError::Duplicate(slug) => {
                write!(f, "module `{slug}` appears twice in the build inputs")
            }
        }
    }
}

impl std::error::Error for BuildKeyError {}

/// The content address of the artifact these inputs compile to:
/// `sha256:` over the canonical JSON of the sorted inputs. Order in
/// [`BuildKeyInputs::releases`] does not affect it; any other input
/// change does.
///
/// The release *digest* is hashed alongside the version, not instead of
/// it: the issue's formula names (crate, exact version), but two
/// publications can carry the same version number with different bytes,
/// and a content address that collided on those would hand customer B
/// customer A's artifact. Provenance binds the same digests to the
/// built files, so the key and the paper trail agree.
///
/// # Panics
///
/// Never; the canonical form is a plain struct with string fields, so
/// its serialization cannot fail — the `expect` documents that
/// invariant.
///
/// # Errors
///
/// A duplicate slug; see [`BuildKeyError`].
pub fn build_key(inputs: &BuildKeyInputs) -> Result<String, BuildKeyError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut sorted: Vec<&PinnedRelease> = inputs.releases.iter().collect();
    sorted.sort_by(|a, b| a.slug.cmp(&b.slug));
    for release in &sorted {
        if !seen.insert(release.slug.as_str()) {
            return Err(BuildKeyError::Duplicate(release.slug.clone()));
        }
    }

    // serde_json emits struct fields in declaration order, so the
    // canonical form is stable for a given crate build — which is all a
    // content address needs: the same inputs, hashed the same way,
    // inside the artifact-producing code path itself.
    // Serialization of a plain struct with string fields cannot fail,
    // so the expect documents an invariant rather than inviting a
    // panic path.
    let json = serde_json::to_string(&ModuleSetInputs::from(inputs))
        .expect("canonical build-key inputs serialize");
    let digest = Sha256::digest(json.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2 + "sha256:".len());
    hex.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// The canonical, sorted projection of [`BuildKeyInputs`] that is
/// hashed. Exists so the sorted shape is a serialisable value rather
/// than an ad-hoc string join — the JSON is what `fz build-key` shows
/// as "the inputs that produced it".
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ModuleSetInputs {
    harness_api: u32,
    rustc_version: String,
    profile: String,
    modules: Vec<SortedRelease>,
}

#[derive(Serialize)]
struct SortedRelease {
    slug: String,
    version: String,
    digest: String,
}

impl From<&BuildKeyInputs> for ModuleSetInputs {
    fn from(inputs: &BuildKeyInputs) -> Self {
        let mut sorted: Vec<&PinnedRelease> = inputs.releases.iter().collect();
        sorted.sort_by(|a, b| a.slug.cmp(&b.slug));
        Self {
            harness_api: inputs.harness_api,
            rustc_version: inputs.rustc_version.clone(),
            profile: inputs.profile.clone(),
            modules: sorted
                .into_iter()
                .map(|r| SortedRelease {
                    slug: r.slug.clone(),
                    version: r.version.clone(),
                    digest: r.digest.clone(),
                })
                .collect(),
        }
    }
}

/// The canonical input JSON `fz build-key` prints, so an operator can
/// see exactly what produced the key. Sorted by slug; field order is
/// the serialization order above.
#[must_use]
pub fn canonical_inputs(inputs: &BuildKeyInputs) -> String {
    serde_json::to_string_pretty(&ModuleSetInputs::from(inputs)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(slug: &str, version: &str) -> PinnedRelease {
        PinnedRelease {
            slug: slug.to_owned(),
            version: version.to_owned(),
            digest: format!("sha256:{}", "0".repeat(64)),
        }
    }

    fn inputs(releases: Vec<PinnedRelease>, harness_api: u32) -> BuildKeyInputs {
        BuildKeyInputs {
            releases,
            harness_api,
            rustc_version: "rustc 1.98.1 (aabbccdde 2026-01-01)".to_owned(),
            profile: BUILD_PROFILE.to_owned(),
        }
    }

    #[test]
    fn reordering_the_module_list_does_not_change_the_key() {
        let a = build_key(&inputs(
            vec![release("cms", "0.1.0"), release("waitlist", "0.2.0")],
            1,
        ))
        .unwrap();
        let b = build_key(&inputs(
            vec![release("waitlist", "0.2.0"), release("cms", "0.1.0")],
            1,
        ))
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn changing_a_module_version_changes_the_key() {
        let a = build_key(&inputs(vec![release("cms", "0.1.0")], 1)).unwrap();
        let b = build_key(&inputs(vec![release("cms", "0.1.1")], 1)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn changing_a_release_digest_changes_the_key_at_the_same_version() {
        // The issue's formula stops at (crate, version); the digest is
        // hashed too because equal version numbers do not imply equal
        // bytes. This is the property that stops a re-published version
        // silently sharing another build's artifact.
        let mut b = inputs(vec![release("cms", "0.1.0")], 1);
        b.releases[0].digest = format!("sha256:{}", "f".repeat(64));
        let a = build_key(&inputs(vec![release("cms", "0.1.0")], 1)).unwrap();
        assert_ne!(a, build_key(&b).unwrap());
    }

    #[test]
    fn changing_harness_api_rustc_or_profile_changes_the_key() {
        let base = build_key(&inputs(vec![release("cms", "0.1.0")], 1)).unwrap();

        let other_api = build_key(&inputs(vec![release("cms", "0.1.0")], 2)).unwrap();
        assert_ne!(base, other_api);

        let mut other_rustc = inputs(vec![release("cms", "0.1.0")], 1);
        other_rustc.rustc_version = "rustc 1.99.0 (x 2026-06-01)".to_owned();
        assert_ne!(base, build_key(&other_rustc).unwrap());

        let mut other_profile = inputs(vec![release("cms", "0.1.0")], 1);
        other_profile.profile = "debug".to_owned();
        assert_ne!(base, build_key(&other_profile).unwrap());
    }

    #[test]
    fn a_duplicate_slug_is_refused_rather_than_ambiguous() {
        let dupes = inputs(vec![release("cms", "0.1.0"), release("cms", "0.2.0")], 1);
        assert!(matches!(
            build_key(&dupes),
            Err(BuildKeyError::Duplicate(slug)) if slug == "cms"
        ));
    }

    #[test]
    fn the_key_is_a_well_formed_sha256_address_and_deterministic() {
        let i = inputs(vec![release("cms", "0.1.0")], 1);
        let key = build_key(&i).unwrap();
        assert!(crate::catalog::is_sha256_digest(&key));
        assert_eq!(key, build_key(&i).unwrap());
    }

    #[test]
    fn the_canonical_inputs_are_slug_sorted_and_carry_every_field() {
        let i = inputs(
            vec![release("waitlist", "0.2.0"), release("cms", "0.1.0")],
            1,
        );
        let json = canonical_inputs(&i);
        let cms = json.find("\"cms\"").expect("cms present");
        let waitlist = json.find("\"waitlist\"").expect("waitlist present");
        assert!(cms < waitlist, "sorted by slug, not input order");
        for field in ["harness-api", "rustc-version", "profile", "modules"] {
            assert!(json.contains(field), "canonical form shows `{field}`");
        }
    }
}
