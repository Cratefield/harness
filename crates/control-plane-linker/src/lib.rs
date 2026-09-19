//! The artifact linker (issue #159): a venture composed from precompiled
//! per-module segments, without invoking cargo.
//!
//! Provisioning's artifact step (`Step::Artifact` in
//! `cratefield-provisioning`) runs behind the [`Deployer`] port, and
//! [`LinkedArtifacts`] is the implementation of that step that does not have
//! to mean a build: given the pinned releases of a module set (the reviewed
//! catalog's pins, issue #139) and per-module **segments** —
//! precompiled bytes already addressed by their release digests — it composes
//! one venture artifact bundle and stores it under the content address the
//! artifact cache already uses ([`build_key()`](cratefield_manifest::build_key::build_key), issue #59). No second cache is
//! invented: the bundle's identity *is* the #59 build key, and a
//! configuration-only change (name, host, config, seed data, sidecar mounts)
//! does not move it, so it finds the cached bundle and composes nothing.
//!
//! Three ports keep the control plane's decisions where they belong:
//!
//! - [`PinSource`] — where the pins come from. The control plane resolves a
//!   venture's module-set key against its own copy of the catalog (issue #5's
//!   deliberate duplication), so the adapter takes pins, not a
//!   [`ModuleSet`]; [`link_pins`] is the linker's own entry point for that
//!   same shape.
//! - [`SegmentSource`] — where per-module segments live. The linker only
//!   requires lookup by `(slug, pinned digest)`; it verifies every segment's
//!   bytes hash to the pinned digest before use, so a store that hands back
//!   the wrong bytes is refused by name, never composed in.
//! - [`ComposedStore`] — where composed bundles live, keyed by build key.
//!   Hits are verified (sha256 of the stored bundle against the recorded
//!   composition digest) so a corrupted entry fails loudly instead of
//!   deploying as someone's venture.
//!
//! In-memory implementations of the segment and store ports exist for tests.
//! Where the real stores physically live remains a control-plane decision
//! (unchanged from #59).
//!
//! ## The fallback ladder
//!
//! The linker is an optimisation on the build path, so it must never turn a
//! set the build path could handle into a failed deploy.
//! [`LinkedArtifacts`] falls back to `inner` — the deployer underneath it —
//! carrying the reason, and the reason is what the provisioning ledger
//! records:
//!
//! - the pin source answers [`Pins::Unavailable`] — the set does not resolve
//!   against the catalog copy, and the source's own reason travels verbatim;
//! - a pin is still the all-zero placeholder digest — no release has been
//!   stamped, so there are no published bytes to compose. The guard names
//!   the release because every placeholder pin is the *same* digest: a
//!   segment store that answered one would hand the same bytes back for
//!   every module;
//! - [`LinkError::SegmentMissing`] — the release is pinned but its
//!   precompiled segment is not published;
//! - [`LinkError::Store`] — a store errored, so the linker got no answer
//!   at all. That is [`LinkError::SegmentMissing`]'s rung reached from the
//!   other side: a store that cannot answer is no more reason to fail the
//!   deploy than one that honestly answers "no", and an optimisation's
//!   outage must not become a failed deploy. The store's own message
//!   travels in the reason.
//!
//! Refused outright, never papered over with a build:
//! [`LinkError::DigestMismatch`] and [`LinkError::CorruptCache`] mean bytes
//! on disk failed the digest they were pinned or recorded under, and
//! [`LinkError::Key`] means the set itself is malformed (a duplicate slug
//! reached the linker without going through resolution) — building it would
//! be equally wrong. Substituting a build there would paper over a
//! verification failure; the deploy stops with the reason instead.
//!
//! ## Honesty about what this is
//!
//! This is the **resolution and composition** half of the linker. It is not a
//! wasm-level link: producing per-module wasm objects and linking them
//! (wasm-bindgen, wasm-opt — where `docs/BUILD-COST.md` shows the time
//! actually goes) is toolchain work nobody has done, and the bundle this
//! produces is a composition artifact, not a deployable `.wasm`. No real
//! release digests exist yet (the catalog pins carry placeholders), so with
//! the [`UnpublishedSegments`] / [`NoStore`] placeholders every real set
//! falls back and the reason is that no release digests are stamped — the
//! linker is wired, but nothing is linked yet. Every measured number in
//! `docs/control-plane/LINKER.md` is over synthetic segments and says so.

#![forbid(unsafe_code)]

use std::collections::HashMap;
// Test/tooling fixtures, not request state (ADR 0007) — the scoped allow
// follows the policy in the workspace `clippy.toml`.
#[allow(clippy::disallowed_types)]
use std::sync::Mutex;

use cratefield_manifest::{
    BUILD_PROFILE, BuildKeyError, BuildKeyInputs, Catalog, ModuleSet, build_key,
    is_placeholder_digest,
};
use cratefield_provisioning::{DeployError, Deployer};

// Implementors of [`PinSource`] have to name [`PinnedRelease`] — it is what
// [`Pins::Published`] carries — and they should not need `cratefield-manifest`
// to do it: the control plane's catalog crate is a deliberate duplicate of the
// manifest one (issue #5), so a caller holding that copy has only this crate
// as a dependency.
pub use cratefield_manifest::PinnedRelease;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The first line of every composed bundle: a format tag, so a consumer can
/// refuse bytes it does not understand rather than misparse them.
pub const BUNDLE_MAGIC: &[u8] = b"cratefield-link-bundle-1\n";

/// The boundary between the bundle's canonical header and the concatenated
/// segments. Part of the digested bytes; changing it changes every digest.
const SEPARATOR: &[u8] = b"\n--segments--\n";

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// The non-module inputs to [`build_key()`](cratefield_manifest::build_key::build_key)
/// and to the bundle header: what the
/// composed artifact is additionally a function of beyond the module set.
/// Mirrors [`BuildKeyInputs`] minus the releases, which come from the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInputs {
    /// The harness API version the segments were compiled against.
    pub harness_api: u32,
    /// The rustc version the segments were compiled by, verbatim
    /// (`rustc --version`). Supplied by the caller — the linker never
    /// spawns a process, so what goes into the key is exactly what the
    /// operator saw.
    pub rustc_version: String,
    /// The build profile. Callers that do not know better want
    /// [`Self::release`], the only profile any deploy path uses.
    pub profile: String,
}

impl LinkInputs {
    /// The deploy-path inputs: the release profile [`BUILD_PROFILE`].
    #[must_use]
    pub fn release(harness_api: u32, rustc_version: impl Into<String>) -> Self {
        Self {
            harness_api,
            rustc_version: rustc_version.into(),
            profile: BUILD_PROFILE.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why linking failed. Every variant names what failed; nothing here is a
/// warning, because a bundle composed around a bad segment would deploy as
/// someone's venture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// No segment exists for this slug under its pinned digest. Either the
    /// release was never built, or the store cannot serve it.
    SegmentMissing { slug: String, digest: String },
    /// The segment's bytes do not hash to the digest the catalog pinned.
    /// The pinned digest is the release's content address; composing bytes
    /// that fail it would be composing something else.
    DigestMismatch {
        slug: String,
        expected: String,
        actual: String,
    },
    /// The cached bundle's bytes do not hash to the composition digest
    /// recorded beside them. A corrupted cache entry must fail the deploy,
    /// not ship.
    CorruptCache { build_key: String },
    /// The build key could not be computed — a duplicate slug reached the
    /// linker without going through resolution. Refused, not fallen back:
    /// the set is malformed, and building it would be equally wrong.
    Key(BuildKeyError),
    /// A store failed, so the linker got no answer at all. This falls back
    /// to the build path like [`LinkError::SegmentMissing`] does — a store
    /// that cannot answer is the same situation as one that honestly
    /// answers "no", and an optimisation's outage must not fail the deploy.
    /// (An integrity failure is the opposite case: there the store *did*
    /// answer, wrongly, and is refused.) Carries the store's own message.
    Store(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::SegmentMissing { slug, digest } => {
                write!(
                    f,
                    "no precompiled segment for module `{slug}` at its pinned digest {digest}; the release was never built or the store cannot serve it"
                )
            }
            LinkError::DigestMismatch {
                slug,
                expected,
                actual,
            } => write!(
                f,
                "segment for `{slug}` hashes to {actual}, not the pinned {expected}; refusing to compose bytes the catalog did not pin"
            ),
            LinkError::CorruptCache { build_key } => write!(
                f,
                "cached artifact for {build_key} does not match its recorded digest; the cache entry is corrupt and the deploy is refused"
            ),
            LinkError::Key(err) => write!(f, "{err}"),
            LinkError::Store(message) => write!(f, "artifact store failed: {message}"),
        }
    }
}

impl std::error::Error for LinkError {}

// ---------------------------------------------------------------------------
// The ports
// ---------------------------------------------------------------------------

/// Where per-module precompiled segments live. Lookup is by the *pinned*
/// digest, not by slug alone: two publications of one version must not be
/// interchangeable, which is the whole reason the digest is in the key.
///
/// A source that cannot find a segment answers `Ok(None)` — the linker
/// refuses with [`LinkError::SegmentMissing`] — and never fabricates bytes.
#[allow(clippy::missing_errors_doc)]
pub trait SegmentSource {
    /// The bytes of `slug`'s pinned release, if the store has them.
    fn segment(&self, slug: &str, digest: &str) -> Result<Option<Vec<u8>>, LinkError>;
}

/// A composed bundle as stored: the bytes and the digest they must hash to.
/// The digest travels beside the bundle so a hit can be verified in one hash
/// without parsing the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedArtifact {
    /// `sha256:` of [`Self::bundle`], as recorded at compose time.
    pub composition_digest: String,
    /// The bundle bytes, [`BUNDLE_MAGIC`] first.
    pub bundle: Vec<u8>,
}

/// Where composed bundles live, keyed by build key. Internal mutability, so
/// [`link`] borrows it immutably — a real store is shared infrastructure,
/// not a scratch pad the linker owns.
#[allow(clippy::missing_errors_doc)]
pub trait ComposedStore {
    /// The stored bundle for this key, if any.
    fn get(&self, build_key: &str) -> Result<Option<CachedArtifact>, LinkError>;
    /// Store the bundle under this key. Content-addressed storage is
    /// idempotent: putting the same key twice stores the same bytes twice.
    fn put(&self, build_key: &str, artifact: &CachedArtifact) -> Result<(), LinkError>;
}

/// An in-memory [`ComposedStore`] — the test and tooling implementation.
/// Where real bundles physically live is a control-plane decision.
#[allow(clippy::disallowed_types)] // test fixture, not request state
#[derive(Default)]
pub struct MemoryStore {
    entries: Mutex<HashMap<String, CachedArtifact>>,
}

impl ComposedStore for MemoryStore {
    fn get(&self, build_key: &str) -> Result<Option<CachedArtifact>, LinkError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| LinkError::Store("memory store poisoned".to_owned()))?
            .get(build_key)
            .cloned())
    }

    fn put(&self, build_key: &str, artifact: &CachedArtifact) -> Result<(), LinkError> {
        self.entries
            .lock()
            .map_err(|_| LinkError::Store("memory store poisoned".to_owned()))?
            .insert(build_key.to_owned(), artifact.clone());
        Ok(())
    }
}

/// A [`ComposedStore`] that keeps nothing: `get` answers `Ok(None)`, `put`
/// answers `Ok(())` and drops. Composed bundles have no durable home yet —
/// a control-plane decision, still open, tracked with the deploy pipeline
/// (#141) — and a caller using this recomposes on every run rather than
/// pretending to cache. Replacing it with a real store is what turns a
/// composed bundle from this run's work into every later run's cache hit.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStore;

impl ComposedStore for NoStore {
    fn get(&self, _build_key: &str) -> Result<Option<CachedArtifact>, LinkError> {
        Ok(None)
    }

    fn put(&self, _build_key: &str, _artifact: &CachedArtifact) -> Result<(), LinkError> {
        Ok(())
    }
}

/// An in-memory [`SegmentSource`] — the test implementation. Real segments
/// come from a release store that does not exist yet; no module has a
/// published digest (the catalog pins are placeholders).
#[allow(clippy::disallowed_types)] // test fixture, not request state
#[derive(Default)]
pub struct MemorySegments {
    segments: Mutex<HashMap<(String, String), Vec<u8>>>,
    fetches: Mutex<usize>,
}

impl MemorySegments {
    /// Store a segment under `(slug, digest)`. The caller is responsible for
    /// the digest matching the bytes — production segments are pinned by the
    /// catalog, and [`link`] verifies regardless.
    ///
    /// # Panics
    ///
    /// Never on valid input; the fixture mutex is only poisoned if a closure
    /// already panicked while holding it.
    pub fn insert(&self, slug: &str, digest: &str, bytes: Vec<u8>) {
        self.segments
            .lock()
            .expect("memory segment store poisoned")
            .insert((slug.to_owned(), digest.to_owned()), bytes);
    }

    /// How many times any segment was fetched. The cache-hit assertion reads
    /// this: a hit path that consults the segment source is a miss in
    /// disguise.
    ///
    /// # Panics
    ///
    /// Never on valid input; the fixture mutex is only poisoned if a closure
    /// already panicked while holding it.
    #[must_use]
    pub fn fetches(&self) -> usize {
        *self.fetches.lock().expect("memory segment store poisoned")
    }
}

impl SegmentSource for MemorySegments {
    fn segment(&self, slug: &str, digest: &str) -> Result<Option<Vec<u8>>, LinkError> {
        *self.fetches.lock().expect("memory segment store poisoned") += 1;
        Ok(self
            .segments
            .lock()
            .map_err(|_| LinkError::Store("memory segment store poisoned".to_owned()))?
            .get(&(slug.to_owned(), digest.to_owned()))
            .cloned())
    }
}

/// A [`SegmentSource`] holding nothing, because no module has a published
/// segment yet: every pin in the published catalog (`CATALOG.json`) is still
/// the all-zero placeholder digest — a release-process gap, documented in
/// `cratefield_manifest::catalog` — so there are no real bytes to hold.
/// `segment` answers `Ok(None)` for everything, which drives
/// [`LinkedArtifacts`]' fallback for every set (or, through [`link_pins`]
/// directly, a [`LinkError::SegmentMissing`]). Replacing it with the real
/// release store is what unlocks the linker for sets that actually exist.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnpublishedSegments;

impl SegmentSource for UnpublishedSegments {
    fn segment(&self, _slug: &str, _digest: &str) -> Result<Option<Vec<u8>>, LinkError> {
        Ok(None)
    }
}

/// Stores are shared infrastructure, not something the linker owns, so
/// borrowing one implements the port: a caller keeps its store and hands the
/// adapter (or [`link`]) a reference.
impl<T: SegmentSource + ?Sized> SegmentSource for &T {
    fn segment(&self, slug: &str, digest: &str) -> Result<Option<Vec<u8>>, LinkError> {
        (**self).segment(slug, digest)
    }
}

/// The borrow form of [`ComposedStore`], for the same reason as the
/// [`SegmentSource`] one above.
impl<T: ComposedStore + ?Sized> ComposedStore for &T {
    fn get(&self, build_key: &str) -> Result<Option<CachedArtifact>, LinkError> {
        (**self).get(build_key)
    }

    fn put(&self, build_key: &str, artifact: &CachedArtifact) -> Result<(), LinkError> {
        (**self).put(build_key, artifact)
    }
}

// ---------------------------------------------------------------------------
// The third port: pins
// ---------------------------------------------------------------------------

/// The pins for a module set — or, when it cannot be linked, why. The
/// failure half is carried as prose because it ends up in the provisioning
/// ledger, where an operator reads it.
///
/// The port is deliberately infallible: the linker is an optimisation and
/// must never be the thing that blocks a provisioning run. A set that cannot
/// be pinned becomes [`Pins::Unavailable`] and the artifact goes through the
/// build path with the reason attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pins {
    /// Every module in the set has a published, pinned release.
    Published(Vec<PinnedRelease>),
    /// The set cannot be linked, and why.
    Unavailable(String),
}

/// Where the pins for a module set come from. [`SegmentSource`] and
/// [`ComposedStore`] answer for bytes; this one answers for the resolution,
/// because the control plane resolves against its own copy of the catalog
/// (issue #5's duplication) and carries the result as the `+`-joined
/// module-set content key, not as a [`ModuleSet`].
pub trait PinSource {
    /// The pinned releases the `+`-joined module-set content key names.
    fn pins(&self, module_set: &str) -> Pins;
}

/// A [`PinSource`] over the manifest crate's own [`Catalog`]: it serves
/// callers already holding that type, which is what the linker's pins are
/// typed over. The control plane is not such a caller — its catalog is the
/// deliberate duplicate (issue #5) in `cratefield-catalog` — so it maps its
/// pins across at the seam instead, in `CuratedPins`
/// (`crates/control-plane-dashboard/src/deployer.rs`). The content key is
/// split on `+` and resolved; any
/// [`ResolveError`](cratefield_manifest::ResolveError) becomes
/// [`Pins::Unavailable`] carrying the resolver's own message, which names
/// the slug that could not be pinned and why.
///
/// Resolution pulling in the core tier and the dependency closure is
/// correct here, not a surprise: the artifact has to contain them.
#[derive(Debug, Clone, Copy)]
pub struct CatalogPins<'a>(pub &'a Catalog);

impl PinSource for CatalogPins<'_> {
    fn pins(&self, module_set: &str) -> Pins {
        let selected: Vec<&str> = module_set.split('+').collect();
        match self.0.resolve(&selected) {
            Ok(set) => Pins::Published(set.releases().to_vec()),
            Err(err) => Pins::Unavailable(format!(
                "module set `{module_set}` does not resolve against the catalog: {err}"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

/// The canonical header of a composed bundle: the build-key inputs and the
/// sorted pins, serialized in declaration order. Struct serialization (not
/// `serde_json::json!`) because the header is digested bytes — its byte form
/// must be stable for the same inputs.
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct BundleHeader<'a> {
    linker: &'static str,
    harness_api: u32,
    rustc_version: &'a str,
    profile: &'a str,
    modules: Vec<HeaderModule<'a>>,
}

#[derive(Serialize)]
struct HeaderModule<'a> {
    slug: &'a str,
    version: &'a str,
    digest: &'a str,
}

/// What [`link`] produced: the bundle, its address, and which path produced
/// it. `source` is the honest answer to "did this go near a compiler or a
/// segment store" — a config-only deploy is a [`Outcome::CacheHit`] and the
/// record should say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedArtifact {
    /// The #59 build key the bundle is stored under. The same key the
    /// cache, provenance and `fz build-key` all speak.
    pub build_key: String,
    /// `sha256:` of [`Self::bytes`].
    pub composition_digest: String,
    /// The module slugs, sorted (the bundle's segment order).
    pub modules: Vec<String>,
    /// Whether this came from the cache or was composed now.
    pub source: Outcome,
    /// The bundle bytes: [`BUNDLE_MAGIC`], the canonical header, the
    /// separator, the segments concatenated in slug order.
    pub bytes: Vec<u8>,
}

/// Which path [`link`] took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The bundle was already stored under this build key; no segment was
    /// fetched and nothing was composed. This is the configuration-only
    /// change path.
    CacheHit,
    /// The segments were fetched, digest-verified and composed into a new
    /// bundle, which was stored.
    Composed,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2 + "sha256:".len());
    hex.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The pins, slug-sorted: the order segments are fetched, verified and laid
/// into the bundle, and the order the header lists them. A composition must
/// be byte-identical however the customer picked the modules, so nothing
/// here may depend on resolution order.
fn sorted_releases(releases: &[PinnedRelease]) -> Vec<&PinnedRelease> {
    let mut sorted: Vec<&PinnedRelease> = releases.iter().collect();
    sorted.sort_by(|a, b| a.slug.cmp(&b.slug));
    sorted
}

/// Link a venture from pins you already hold: resolve every pinned release
/// to its precompiled segment, verify each against its digest, and compose
/// the bundle — or return the stored one when this build key is already
/// cached.
///
/// This is the entry point for callers that have pins but no
/// [`ModuleSet`] — the control plane resolves a venture against its own
/// catalog copy and carries the `+`-joined content key, not the set
/// (issue #5's duplication). `releases` may be in any order: the bundle is
/// laid out in slug order either way, so the same pins compose the same
/// bytes. [`link`] is this function with a resolved set's own releases.
///
/// The cache is consulted **first** and a hit touches nothing else: no
/// segment fetch, no hashing of segment bytes. That is the property a
/// configuration-only change needs — the key does not move, so the stored
/// bundle is still exactly the artifact this set names.
///
/// # Errors
///
/// [`LinkError::SegmentMissing`] when a pinned release has no precompiled
/// segment; [`LinkError::DigestMismatch`] when one's bytes fail its pin;
/// [`LinkError::CorruptCache`] when a hit's bytes fail their recorded
/// digest; [`LinkError::Key`] on a duplicate slug; [`LinkError::Store`] when
/// a store fails.
pub fn link_pins(
    releases: &[PinnedRelease],
    inputs: &LinkInputs,
    segments: &impl SegmentSource,
    store: &impl ComposedStore,
) -> Result<LinkedArtifact, LinkError> {
    let key = build_key(&BuildKeyInputs {
        releases: releases.to_vec(),
        harness_api: inputs.harness_api,
        rustc_version: inputs.rustc_version.clone(),
        profile: inputs.profile.clone(),
    })
    .map_err(LinkError::Key)?;

    if let Some(cached) = store.get(&key)? {
        let actual = sha256_hex(&cached.bundle);
        if actual != cached.composition_digest {
            return Err(LinkError::CorruptCache { build_key: key });
        }
        return Ok(LinkedArtifact {
            modules: sorted_releases(releases)
                .iter()
                .map(|r| r.slug.clone())
                .collect(),
            build_key: key,
            composition_digest: cached.composition_digest,
            source: Outcome::CacheHit,
            bytes: cached.bundle,
        });
    }

    let sorted = sorted_releases(releases);
    let mut payload = Vec::new();
    for release in &sorted {
        let bytes = segments
            .segment(&release.slug, &release.digest)?
            .ok_or_else(|| LinkError::SegmentMissing {
                slug: release.slug.clone(),
                digest: release.digest.clone(),
            })?;
        let actual = sha256_hex(&bytes);
        if actual != release.digest {
            return Err(LinkError::DigestMismatch {
                slug: release.slug.clone(),
                expected: release.digest.clone(),
                actual,
            });
        }
        payload.extend_from_slice(&bytes);
    }

    let header = serde_json::to_vec(&BundleHeader {
        linker: "cratefield-link-bundle-1",
        harness_api: inputs.harness_api,
        rustc_version: &inputs.rustc_version,
        profile: &inputs.profile,
        modules: sorted
            .iter()
            .map(|r| HeaderModule {
                slug: &r.slug,
                version: &r.version,
                digest: &r.digest,
            })
            .collect(),
    })
    .map_err(|err| LinkError::Store(format!("bundle header failed to serialize: {err}")))?;

    let mut bundle =
        Vec::with_capacity(BUNDLE_MAGIC.len() + header.len() + SEPARATOR.len() + payload.len());
    bundle.extend_from_slice(BUNDLE_MAGIC);
    bundle.extend_from_slice(&header);
    bundle.extend_from_slice(SEPARATOR);
    bundle.extend_from_slice(&payload);

    let composition_digest = sha256_hex(&bundle);
    store.put(
        &key,
        &CachedArtifact {
            composition_digest: composition_digest.clone(),
            bundle: bundle.clone(),
        },
    )?;

    Ok(LinkedArtifact {
        modules: sorted.iter().map(|r| r.slug.clone()).collect(),
        build_key: key,
        composition_digest,
        source: Outcome::Composed,
        bytes: bundle,
    })
}

/// Link a venture's resolved set: the [`ModuleSet`] form of [`link_pins`],
/// which does the work; this wrapper hands it the set's own releases.
///
/// The cache is consulted **first** and a hit touches nothing else: no
/// segment fetch, no hashing of segment bytes. That is the property a
/// configuration-only change needs — the key does not move, so the stored
/// bundle is still exactly the artifact this set names.
///
/// # Errors
///
/// [`LinkError::SegmentMissing`] when a pinned release has no precompiled
/// segment; [`LinkError::DigestMismatch`] when one's bytes fail its pin;
/// [`LinkError::CorruptCache`] when a hit's bytes fail their recorded
/// digest; [`LinkError::Key`] on a duplicate slug; [`LinkError::Store`] when
/// a store fails.
pub fn link(
    set: &ModuleSet,
    inputs: &LinkInputs,
    segments: &impl SegmentSource,
    store: &impl ComposedStore,
) -> Result<LinkedArtifact, LinkError> {
    link_pins(set.releases(), inputs, segments, store)
}

// ---------------------------------------------------------------------------
// The provisioning adapter
// ---------------------------------------------------------------------------

/// Provisioning's artifact step with the linker in front of the build: a
/// [`Deployer`] whose `build_artifact` composes the set from published
/// segments when it can, and calls `inner` — carrying the reason — when it
/// legitimately cannot (the fallback ladder is in the crate docs). The other
/// six steps are `inner`'s, delegated verbatim: this adapter exists for one
/// step and does not pretend otherwise.
///
/// `build_artifact` takes the module set as its content key — the
/// `+`-joined slug list the port already carries — which is what
/// [`PinSource`] resolves.
///
/// [`UnpublishedSegments`] with [`NoStore`] is the shape the control plane
/// has today: resolution works, nothing is published, so every set falls
/// back and the recorded reason says which gap.
pub struct LinkedArtifacts<P, S, C, D> {
    pins: P,
    inputs: LinkInputs,
    segments: S,
    store: C,
    inner: D,
}

impl<P, S, C, D> LinkedArtifacts<P, S, C, D> {
    /// Assemble the adapter from its four decisions and the deployer under
    /// it. The fields are owned, so a caller can build one in a single
    /// expression; pass stores behind a reference to keep owning them.
    #[must_use]
    pub fn new(pins: P, inputs: LinkInputs, segments: S, store: C, inner: D) -> Self {
        Self {
            pins,
            inputs,
            segments,
            store,
            inner,
        }
    }
}

impl<P: PinSource, S: SegmentSource, C: ComposedStore, D: Deployer> LinkedArtifacts<P, S, C, D> {
    /// Hand the set to the build path, with `why` the linker could not
    /// serve it. The inner error's text survives verbatim: the recorded
    /// message must keep saying what actually stopped the run, not only
    /// what pushed it to a build.
    async fn fall_back(&self, module_set: &str, why: String) -> Result<(), DeployError> {
        let reason = format!("{why}, so the artifact still needs a build");
        match self.inner.build_artifact(module_set).await {
            Ok(()) => Ok(()),
            Err(inner) => Err(DeployError::new(format!("{reason}. {inner}"))),
        }
    }
}

impl<P: PinSource, S: SegmentSource, C: ComposedStore, D: Deployer> Deployer
    for LinkedArtifacts<P, S, C, D>
{
    async fn build_artifact(&self, module_set: &str) -> Result<(), DeployError> {
        let releases = match self.pins.pins(module_set) {
            Pins::Unavailable(why) => return self.fall_back(module_set, why).await,
            Pins::Published(releases) => releases,
        };
        // Every placeholder pin is the same digest, so this is checked
        // before the segment store is trusted at all: a store that answered
        // one placeholder would answer them all with the same bytes.
        if let Some(pin) = releases.iter().find(|r| is_placeholder_digest(&r.digest)) {
            return self
                .fall_back(
                    module_set,
                    format!(
                        "`{}` release `{}` is pinned to the all-zero placeholder digest the \
                         catalog ships until release stamping",
                        pin.slug, pin.version
                    ),
                )
                .await;
        }
        match link_pins(&releases, &self.inputs, &self.segments, &self.store) {
            // Composed now, or served from the store: either way **no build
            // happened**, which is the property this adapter exists for.
            Ok(_) => Ok(()),
            Err(LinkError::SegmentMissing { slug, digest }) => {
                self.fall_back(
                    module_set,
                    format!("`{slug}` has no precompiled segment at its pinned digest {digest}"),
                )
                .await
            }
            // A store that errored gave no answer at all — the same rung
            // as a missing segment, reached from the other side. Falling
            // back keeps the optimisation's outage from becoming a failed
            // deploy; the reason carries the store's own message.
            Err(err @ LinkError::Store(_)) => self.fall_back(module_set, err.to_string()).await,
            // Refusals, not reasons to build: bytes that fail their pin, a
            // corrupt cache entry, or a malformed set must not be papered
            // over by rebuilding.
            Err(err) => Err(DeployError::new(format!(
                "the artifact linker refused to compose this set and did not fall back to a \
                 build: {err}"
            ))),
        }
    }

    async fn ensure_database(&self, tenant: &str) -> Result<(), DeployError> {
        self.inner.ensure_database(tenant).await
    }

    async fn ensure_worker(&self, tenant: &str, module_set: &str) -> Result<(), DeployError> {
        self.inner.ensure_worker(tenant, module_set).await
    }

    async fn apply_schema(&self, tenant: &str, module_set: &str) -> Result<(), DeployError> {
        self.inner.apply_schema(tenant, module_set).await
    }

    async fn seed_secrets(&self, tenant: &str) -> Result<(), DeployError> {
        self.inner.seed_secrets(tenant).await
    }

    async fn bind_route(&self, tenant: &str, subdomain: &str) -> Result<(), DeployError> {
        self.inner.bind_route(tenant, subdomain).await
    }

    async fn health_ok(&self, subdomain: &str) -> Result<bool, DeployError> {
        self.inner.health_ok(subdomain).await
    }
}
