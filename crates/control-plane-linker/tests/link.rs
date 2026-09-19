//! The linker's contract, end to end over the public API: what composes,
//! what is refused, and which path each case takes.
//!
//! Every test here guards a property that can silently rot: the hit path
//! fetching segments, a bad segment being composed in, a corrupt cache entry
//! shipping. The bundle is digested bytes, so the determinism assertions are
//! byte assertions, not equality-of-convenience.

use cratefield_linker::{
    CachedArtifact, CatalogPins, ComposedStore, LinkError, LinkInputs, LinkedArtifacts,
    MemorySegments, MemoryStore, NoStore, Outcome, PinSource, Pins, SegmentSource,
    UnpublishedSegments, link,
};
use cratefield_manifest::{Catalog, CatalogModule, ModuleRelease, ReleaseReview, Tier, builtin};
use cratefield_provisioning::{DeployError, Deployer};
// `Mutex` is a test/tooling fixture here, not request state (ADR 0007) —
// the scoped allow follows the policy in the workspace `clippy.toml`.
#[allow(clippy::disallowed_types)]
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Fixtures: a catalog whose pins are real digests of synthetic segments.
// ---------------------------------------------------------------------------

fn pseudo_bytes(seed: u8, len: usize) -> Vec<u8> {
    // Deterministic, cheap, not all-same: xorshift over the seed.
    let mut state = u32::from(seed) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state & 0xff) as u8
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2 + "sha256:".len());
    hex.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn module(slug: &str, seed: u8, tier: Tier, depends_on: &[&str]) -> (CatalogModule, Vec<u8>) {
    let bytes = pseudo_bytes(seed, 4096);
    let entry = CatalogModule {
        slug: slug.to_owned(),
        name: slug.to_owned(),
        summary: format!("the {slug} module"),
        tier,
        depends_on: depends_on.iter().map(|s| (*s).to_owned()).collect(),
        releases: vec![ModuleRelease {
            version: "0.1.0".to_owned(),
            digest: sha256_hex(&bytes),
            review: ReleaseReview::Approved {
                reviewer: "test".to_owned(),
                reviewed_at: "2026-09-13T00:00:00Z".to_owned(),
            },
        }],
    };
    (entry, bytes)
}

/// A catalog of six modules (`core` plus five optional), and the segments
/// matching its pins, exactly as a release store would hold them.
fn six_modules() -> (Catalog, MemorySegments) {
    let (core, core_bytes) = module("core", 1, Tier::Core, &[]);
    let (email_signup, email_bytes) = module("email-signup", 2, Tier::Optional, &[]);
    let (waitlist, waitlist_bytes) = module("waitlist", 3, Tier::Optional, &[]);
    let (cms, cms_bytes) = module("cms", 4, Tier::Optional, &[]);
    let (notifications, notifications_bytes) =
        module("notifications", 5, Tier::Optional, &["core"]);
    let (privacy, privacy_bytes) = module("privacy", 6, Tier::Optional, &["core"]);
    let catalog = Catalog {
        modules: vec![core, email_signup, waitlist, cms, notifications, privacy],
    };
    let segments = MemorySegments::default();
    for (slug, bytes) in [
        ("core", core_bytes),
        ("email-signup", email_bytes),
        ("waitlist", waitlist_bytes),
        ("cms", cms_bytes),
        ("notifications", notifications_bytes),
        ("privacy", privacy_bytes),
    ] {
        segments.insert(slug, &sha256_hex(&bytes), bytes);
    }
    (catalog, segments)
}

fn inputs() -> LinkInputs {
    LinkInputs::release(HARNESS_API, "rustc 1.98.1 (test 2026-09-13)")
}

fn resolve(catalog: &Catalog, selected: &[&str]) -> cratefield_manifest::ModuleSet {
    catalog
        .resolve(selected)
        .expect("fixture selection resolves")
}

// A store that lies: hands back a bundle with one flipped byte under the
// original digest. This is the shape a corrupted cache entry takes, and the
// only way to produce one through the public API is to interpose it here.
struct CorruptingStore(MemoryStore);

impl ComposedStore for CorruptingStore {
    fn get(&self, build_key: &str) -> Result<Option<CachedArtifact>, LinkError> {
        Ok(self.0.get(build_key)?.map(|mut cached| {
            let last = cached.bundle.len() - 1;
            cached.bundle[last] ^= 0xff;
            cached
        }))
    }

    fn put(&self, build_key: &str, artifact: &CachedArtifact) -> Result<(), LinkError> {
        self.0.put(build_key, artifact)
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
fn composition_is_deterministic_and_pick_order_independent() {
    let (catalog, segments) = six_modules();
    // The same five optional modules, selected in two orders.
    let one = resolve(
        &catalog,
        &[
            "email-signup",
            "waitlist",
            "cms",
            "notifications",
            "privacy",
        ],
    );
    let two = resolve(
        &catalog,
        &[
            "privacy",
            "cms",
            "waitlist",
            "notifications",
            "email-signup",
        ],
    );
    // ModuleSet's own equality includes resolution order (dependencies
    // before dependants), which legitimately differs by pick order; the
    // *set* — what keys the artifact — is the sorted releases.
    let sorted = |set: &cratefield_manifest::ModuleSet| {
        let mut releases = set.releases().to_vec();
        releases.sort_by(|a, b| a.slug.cmp(&b.slug));
        releases
    };
    assert_eq!(
        sorted(&one),
        sorted(&two),
        "the same set resolved in either pick order"
    );

    let first = link(&one, &inputs(), &segments, &MemoryStore::default()).unwrap();
    let second = link(&two, &inputs(), &segments, &MemoryStore::default()).unwrap();

    assert_eq!(
        first.bytes, second.bytes,
        "identical sets compose byte-identical bundles"
    );
    assert_eq!(first.build_key, second.build_key);
    assert_eq!(first.composition_digest, second.composition_digest);
    // The bundle's segments are slug-sorted, whatever the pick order was.
    let mut sorted: Vec<&str> = one.slugs().iter().map(String::as_str).collect();
    sorted.sort_unstable();
    assert_eq!(
        first.modules,
        sorted.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()
    );
}

#[test]
fn the_bundle_shape_is_magic_header_separator_segments() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["email-signup"]);
    let artifact = link(&set, &inputs(), &segments, &MemoryStore::default()).unwrap();

    assert!(artifact.bytes.starts_with(cratefield_linker::BUNDLE_MAGIC));
    let rest = &artifact.bytes[cratefield_linker::BUNDLE_MAGIC.len()..];
    let sep = b"\n--segments--\n";
    let split = rest
        .windows(sep.len())
        .position(|w| w == sep)
        .expect("the header/segment separator is present");
    let header: serde_json::Value =
        serde_json::from_slice(&rest[..split]).expect("the header is canonical JSON");
    assert_eq!(header["linker"], "cratefield-link-bundle-1");
    assert_eq!(header["harness-api"], u64::from(HARNESS_API));
    let modules = header["modules"].as_array().expect("header lists modules");
    assert_eq!(modules.len(), 2, "email-signup plus the core module");
    assert_eq!(modules[0]["slug"], "core", "header modules are slug-sorted");

    // The payload is exactly the pinned segments, concatenated in slug order.
    let mut payload = Vec::new();
    for slug in ["core", "email-signup"] {
        let release = set.release(slug).unwrap();
        payload.extend_from_slice(&segments.segment(slug, &release.digest).unwrap().unwrap());
    }
    assert_eq!(
        &rest[split + sep.len()..],
        &payload[..],
        "segments concatenated in slug order"
    );
}

#[test]
fn a_segment_failing_its_pin_is_refused_by_name_and_nothing_is_stored() {
    let (catalog, segments) = six_modules();
    // Sabotage one module: its stored bytes no longer match the pinned
    // digest (the catalog's pin is right; the store's bytes are wrong).
    let wrong = pseudo_bytes(99, 4096);
    segments.insert("cms", &sha256_hex(&pseudo_bytes(4, 4096)), wrong);

    let set = resolve(&catalog, &["cms"]);
    let store = MemoryStore::default();
    let err = link(&set, &inputs(), &segments, &store).unwrap_err();

    match err {
        LinkError::DigestMismatch {
            slug,
            expected,
            actual,
        } => {
            assert_eq!(slug, "cms");
            assert_eq!(expected, set.release("cms").unwrap().digest);
            assert_eq!(actual, sha256_hex(&pseudo_bytes(99, 4096)));
        }
        other => panic!("expected a digest mismatch naming `cms`, got {other:?}"),
    }
    assert!(
        store
            .get(
                &cratefield_manifest::build_key(&cratefield_manifest::BuildKeyInputs {
                    releases: set.releases().to_vec(),
                    harness_api: inputs().harness_api,
                    rustc_version: inputs().rustc_version,
                    profile: inputs().profile,
                })
                .unwrap()
            )
            .unwrap()
            .is_none(),
        "refused composition stores nothing"
    );
}

#[test]
fn a_missing_segment_is_refused_and_names_the_release() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["notifications"]);
    // `notifications` pulls in `core`; drop only `notifications`' segment.
    let release = set.release("notifications").unwrap();
    segments
        .segment("notifications", &release.digest)
        .unwrap()
        .unwrap();
    // Empty the source of just that module by rebuilding the store without it.
    let fresh = MemorySegments::default();
    let core = set.release("core").unwrap();
    fresh.insert(
        "core",
        &core.digest,
        segments.segment("core", &core.digest).unwrap().unwrap(),
    );

    match link(&set, &inputs(), &fresh, &MemoryStore::default()).unwrap_err() {
        LinkError::SegmentMissing { slug, digest } => {
            assert_eq!(slug, "notifications");
            assert_eq!(digest, release.digest);
        }
        other => panic!("expected a missing-segment refusal, got {other:?}"),
    }
}

#[test]
fn a_cache_hit_fetches_no_segments_and_returns_the_same_bundle() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["email-signup", "waitlist"]);
    let store = MemoryStore::default();

    let first = link(&set, &inputs(), &segments, &store).unwrap();
    assert_eq!(first.source, Outcome::Composed);
    let misses = segments.fetches();
    // `core` is always included, so the set is three modules.
    assert_eq!(misses, 3, "compose fetched one segment per module");

    // The second link has never seen these segments.
    let fresh_source = MemorySegments::default();
    let second = link(&set, &inputs(), &fresh_source, &store).unwrap();
    assert_eq!(second.source, Outcome::CacheHit);
    assert_eq!(fresh_source.fetches(), 0, "a hit consults no segment store");
    assert_eq!(second.bytes, first.bytes);
    assert_eq!(second.composition_digest, first.composition_digest);
    assert_eq!(second.modules, first.modules);
}

#[test]
fn a_configuration_only_change_is_a_cache_hit() {
    // The amended #59 criterion, at the linker: nothing about a venture's
    // name, host, config, seed data or sidecar mounts enters the build key,
    // so the config-only path cannot even reach the segments. The inputs
    // here are deliberately identical to prove the linker needs nothing
    // more: if config ever leaked into the key, this test's premise breaks
    // and the golden wire-form test in cratefield-manifest fails first.
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["email-signup"]);
    let store = MemoryStore::default();

    let before = link(&set, &inputs(), &segments, &store).unwrap();
    // ...the customer renames the venture, changes the host, mounts a
    // sidecar: none of which is visible to `link` ...
    let after = link(&set, &inputs(), &segments, &store).unwrap();

    assert_eq!(after.source, Outcome::CacheHit);
    assert_eq!(after.build_key, before.build_key);
    assert_eq!(after.bytes, before.bytes);
}

#[test]
fn a_corrupt_cache_entry_is_refused_not_shipped() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["email-signup"]);

    let honest = MemoryStore::default();
    link(&set, &inputs(), &segments, &honest).unwrap();

    let err = link(&set, &inputs(), &segments, &CorruptingStore(honest)).unwrap_err();
    assert!(matches!(err, LinkError::CorruptCache { .. }), "got {err}");
    assert!(
        err.to_string().contains("corrupt"),
        "the message says what happened: {err}"
    );
}

#[test]
fn changing_a_pinned_version_composes_a_new_bundle_not_the_old_one() {
    let (mut catalog, segments) = six_modules();
    // Re-release `waitlist` at 0.1.1 with different bytes.
    let new_bytes = pseudo_bytes(77, 4096);
    let waitlist = catalog
        .modules
        .iter_mut()
        .find(|m| m.slug == "waitlist")
        .unwrap();
    waitlist.releases.insert(
        0,
        ModuleRelease {
            version: "0.1.1".to_owned(),
            digest: sha256_hex(&new_bytes),
            review: ReleaseReview::Approved {
                reviewer: "test".to_owned(),
                reviewed_at: "2026-09-13T00:00:00Z".to_owned(),
            },
        },
    );
    segments.insert("waitlist", &sha256_hex(&new_bytes), new_bytes);

    let old_set = resolve(&six_modules().0, &["waitlist"]);
    let new_set = resolve(&catalog, &["waitlist"]);
    let store = MemoryStore::default();

    let old = link(&old_set, &inputs(), &segments, &store).unwrap();
    let new = link(&new_set, &inputs(), &segments, &store).unwrap();

    assert_ne!(old.build_key, new.build_key, "the pin is in the key");
    assert_eq!(new.source, Outcome::Composed);
    assert_ne!(old.bytes, new.bytes);
}

/// Min, p50, p99 and max over a sample set, with the count they came
/// from — the reporting shape `docs/BENCHMARKS.md` publishes and
/// `bench/write-ceiling` prints. The percentile indexes are the bench's
/// exact integer picks, so the same samples print the same percentiles
/// everywhere.
struct Summary {
    n: usize,
    min: std::time::Duration,
    p50: std::time::Duration,
    p99: std::time::Duration,
    max: std::time::Duration,
}

impl Summary {
    fn new(mut samples: Vec<std::time::Duration>) -> Self {
        assert!(
            !samples.is_empty(),
            "a measurement is nothing without samples"
        );
        samples.sort_unstable();
        let at = |pct: usize| samples[(samples.len() - 1) * pct / 100];
        Self {
            n: samples.len(),
            min: samples[0],
            p50: at(50),
            p99: at(99),
            max: samples[samples.len() - 1],
        }
    }
}

/// The measurement behind `docs/control-plane/LINKER.md`: six synthetic
/// segments (24 KiB total), timed cold and on a hit — many samples per
/// path, never one, because a single timing cannot be told apart from a
/// scheduler hiccup and a fluctuation read as a cause is exactly what
/// `docs/BENCHMARKS.md`'s rules exist to prevent. Prints min / p50 / p99 /
/// max with the sample count, and asserts only the structural facts the
/// numbers depend on (every cold sample really composed, every hit really
/// hit) — wall-clock assertions would flake CI; the doc carries the
/// numbers.
#[test]
fn measured_cold_compose_and_cache_hit() {
    const COLD_SAMPLES: usize = 100;
    const HIT_SAMPLES: usize = 200;

    let (catalog, segments) = six_modules();
    let set = resolve(
        &catalog,
        &[
            "email-signup",
            "waitlist",
            "cms",
            "notifications",
            "privacy",
        ],
    );

    // One untimed compose to page the resolver and hasher in; the timed
    // samples below are not first-touch costs.
    let warmed = link(&set, &inputs(), &segments, &MemoryStore::default()).unwrap();
    let payload: usize = set
        .releases()
        .iter()
        .map(|r| segments.segment(&r.slug, &r.digest).unwrap().unwrap().len())
        .sum();

    // Cold: a fresh store per sample, so every sample really is cold.
    let mut cold = Vec::with_capacity(COLD_SAMPLES);
    for _ in 0..COLD_SAMPLES {
        let start = std::time::Instant::now();
        let composed = link(&set, &inputs(), &segments, &MemoryStore::default()).unwrap();
        cold.push(start.elapsed());
        assert_eq!(composed.source, Outcome::Composed);
    }

    // Hit: one store holding the bundle, then hits only.
    let store = MemoryStore::default();
    link(&set, &inputs(), &segments, &store).unwrap();
    let mut hit = Vec::with_capacity(HIT_SAMPLES);
    for _ in 0..HIT_SAMPLES {
        let start = std::time::Instant::now();
        let served = link(&set, &inputs(), &segments, &store).unwrap();
        hit.push(start.elapsed());
        assert_eq!(served.source, Outcome::CacheHit);
    }

    let cold = Summary::new(cold);
    let hit = Summary::new(hit);
    println!(
        "cold compose: n={} min={:?} p50={:?} p99={:?} max={:?} \
         (a fresh store per sample; {} segments, {payload} bytes, bundle {} bytes)\n\
         hit:          n={} min={:?} p50={:?} p99={:?} max={:?}",
        cold.n,
        cold.min,
        cold.p50,
        cold.p99,
        cold.max,
        set.releases().len(),
        warmed.bytes.len(),
        hit.n,
        hit.min,
        hit.p50,
        hit.p99,
        hit.max,
    );
}

/// The harness API version the fixture segments were "compiled" against. The
// real value is `cratefield_core::HARNESS_API`; the linker takes it as an
// input, and the fixture pins a literal so the test does not need the
// harness itself.
const HARNESS_API: u32 = 1;

// A segment source is a port; a source that fails must fail the link, not
/// compose around the hole.
struct FailingSource;

impl SegmentSource for FailingSource {
    fn segment(&self, _slug: &str, _digest: &str) -> Result<Option<Vec<u8>>, LinkError> {
        Err(LinkError::Store("release store unreachable".to_owned()))
    }
}

#[test]
fn a_failing_segment_source_fails_the_link() {
    let (catalog, _) = six_modules();
    let set = resolve(&catalog, &["email-signup"]);
    let err = link(&set, &inputs(), &FailingSource, &MemoryStore::default()).unwrap_err();
    assert!(matches!(err, LinkError::Store(_)), "got {err}");
}

/// A failing segment source through the port falls back to the build path
/// carrying the store's own reason: a store that errored gave no answer at
/// all, which is the missing-segment rung reached from the other side, not
/// an integrity failure to refuse over. Refusing there would turn the
/// optimisation's outage into a failed deploy.
#[pollster::test]
async fn a_failing_segment_source_falls_back_carrying_the_store_s_reason() {
    let (catalog, _) = six_modules();
    let set = resolve(&catalog, &["email-signup"]);
    let module_set = set.content_key();
    let store = MemoryStore::default();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(
        CatalogPins(&catalog),
        inputs(),
        FailingSource,
        &store,
        inner,
    );

    let err = port.build_artifact(&module_set).await.unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("artifact store failed: release store unreachable"),
        "the reason names the store failure: {message}"
    );
    assert!(
        message.contains("so the artifact still needs a build"),
        "it fell back rather than refused: {message}"
    );
    assert!(
        message.contains("no deployer is wired"),
        "the inner refusal's text survives verbatim: {message}"
    );
    assert_eq!(
        counts.lock().expect("counting deployer poisoned").builds,
        [module_set.as_str()],
        "the build path was the fallback"
    );
}

// ---------------------------------------------------------------------------
// The provisioning adapter: the linker as provisioning's artifact step
// ---------------------------------------------------------------------------

/// What the inner deployer was asked, one list per step. The artifact step
/// is the only one the adapter is allowed to change, so the delegation test
/// asserts every other list verbatim.
#[derive(Default)]
struct Calls {
    builds: Vec<String>,
    databases: Vec<String>,
    workers: Vec<(String, String)>,
    schemas: Vec<(String, String)>,
    secrets: Vec<String>,
    routes: Vec<String>,
    healths: Vec<String>,
}

/// The inner deployer the port is composed over: counts every call, and
/// refuses the artifact step in `Unwired`'s own words, so the composed
/// fallback messages assert something a real resume would record.
#[allow(clippy::disallowed_types)] // test fixture, not request state
struct CountingDeployer {
    calls: Arc<Mutex<Calls>>,
}

#[allow(clippy::disallowed_types)] // test fixture, not request state
impl CountingDeployer {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Calls::default())),
        }
    }

    /// A handle that outlives the adapter: the port owns the deployer, the
    /// assertions read the same counters through this.
    fn handle(&self) -> Arc<Mutex<Calls>> {
        Arc::clone(&self.calls)
    }
}

// The counting fake never awaits anything; the port is async because a real
// deployer is (same shape as the fakes in `cratefield-provisioning`).
#[allow(clippy::unused_async_trait_impl)]
impl Deployer for CountingDeployer {
    async fn build_artifact(&self, module_set: &str) -> Result<(), DeployError> {
        self.calls
            .lock()
            .expect("counting deployer poisoned")
            .builds
            .push(module_set.to_owned());
        Err(DeployError::new(
            "no deployer is wired: building the composed artifact needs an adapter that talks to \
             Cloudflare, and the control plane has none yet. Nothing was changed.",
        ))
    }

    async fn ensure_database(&self, tenant: &str) -> Result<(), DeployError> {
        self.calls
            .lock()
            .expect("counting deployer poisoned")
            .databases
            .push(tenant.to_owned());
        Ok(())
    }

    async fn ensure_worker(&self, tenant: &str, module_set: &str) -> Result<(), DeployError> {
        self.calls
            .lock()
            .expect("counting deployer poisoned")
            .workers
            .push((tenant.to_owned(), module_set.to_owned()));
        Ok(())
    }

    async fn apply_schema(&self, tenant: &str, module_set: &str) -> Result<(), DeployError> {
        self.calls
            .lock()
            .expect("counting deployer poisoned")
            .schemas
            .push((tenant.to_owned(), module_set.to_owned()));
        Ok(())
    }

    async fn seed_secrets(&self, tenant: &str) -> Result<(), DeployError> {
        self.calls
            .lock()
            .expect("counting deployer poisoned")
            .secrets
            .push(tenant.to_owned());
        Ok(())
    }

    async fn bind_route(&self, _tenant: &str, subdomain: &str) -> Result<(), DeployError> {
        self.calls
            .lock()
            .expect("counting deployer poisoned")
            .routes
            .push(subdomain.to_owned());
        Ok(())
    }

    async fn health_ok(&self, subdomain: &str) -> Result<bool, DeployError> {
        self.calls
            .lock()
            .expect("counting deployer poisoned")
            .healths
            .push(subdomain.to_owned());
        Ok(true)
    }
}

/// The amended #59 criterion, at the port: a configuration-only change
/// (name, host, config, seed data, sidecar mounts) does not move the build
/// key, so the second run is served from the store — no segment fetched,
/// and the inner deployer's build path never reached.
#[pollster::test]
async fn a_configuration_only_change_through_the_port_does_not_reach_the_build_path() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["email-signup"]);
    let module_set = set.content_key();
    let store = MemoryStore::default();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &segments, &store, inner);

    port.build_artifact(&module_set).await.unwrap();
    let misses = segments.fetches();
    assert_eq!(misses, 2, "the compose fetched one segment per module");
    assert!(
        counts
            .lock()
            .expect("counting deployer poisoned")
            .builds
            .is_empty(),
        "the linker composed it, so the build path was never reached"
    );

    // ...the customer renames the venture, changes the host, mounts a
    // sidecar: none of which is visible to the key ...
    port.build_artifact(&module_set).await.unwrap();
    assert_eq!(
        segments.fetches(),
        misses,
        "the second run was served from the store and consulted no segment source"
    );
    assert!(
        counts
            .lock()
            .expect("counting deployer poisoned")
            .builds
            .is_empty(),
        "a cache hit does not build either"
    );
}

/// A set this port has not seen composes through the linker and lands in
/// the store under the set's own #59 build key — the build path still
/// untouched.
#[pollster::test]
async fn a_new_module_set_composes_through_the_port_without_reaching_the_build_path() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["email-signup", "cms"]);
    let module_set = set.content_key();
    let store = MemoryStore::default();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &segments, &store, inner);

    port.build_artifact(&module_set).await.unwrap();

    assert!(
        counts
            .lock()
            .expect("counting deployer poisoned")
            .builds
            .is_empty(),
        "the linker composed the new set; the build path was never reached"
    );
    let key = cratefield_manifest::build_key(&cratefield_manifest::BuildKeyInputs {
        releases: set.releases().to_vec(),
        harness_api: inputs().harness_api,
        rustc_version: inputs().rustc_version.clone(),
        profile: inputs().profile.clone(),
    })
    .unwrap();
    assert!(
        store.get(&key).unwrap().is_some(),
        "the composed bundle is stored under the #59 build key"
    );
}

/// The adapter over `builtin()`'s pins: the real catalog resolves fine —
/// the placeholder gate lives in the adapter, not in the pin source — so
/// this is the check that the gate itself falls back, names the release,
/// and keeps the inner refusal's text verbatim for the ledger.
#[pollster::test]
async fn a_placeholder_pin_falls_back_to_the_build_path_and_names_the_release() {
    let catalog = builtin();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(
        CatalogPins(&catalog),
        inputs(),
        UnpublishedSegments,
        NoStore,
        inner,
    );

    let err = port.build_artifact("email-signup").await.unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("all-zero placeholder"),
        "the reason names the placeholder: {message}"
    );
    assert!(
        message.contains("`email-signup` release `0.1.1`"),
        "the reason names the release: {message}"
    );
    assert!(
        message.contains("no deployer is wired"),
        "the inner refusal's text survives verbatim: {message}"
    );
    assert_eq!(
        counts.lock().expect("counting deployer poisoned").builds,
        ["email-signup".to_owned()],
        "the build path was the fallback"
    );
}

/// A pinned release whose precompiled segment was never published falls
/// back and names that release.
#[pollster::test]
async fn a_missing_segment_falls_back_to_the_build_path_and_names_the_release() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["notifications"]);
    // Every segment but `notifications`' is published. `core` is pulled in
    // by resolution and links fine; the set stops at `notifications`.
    let fresh = MemorySegments::default();
    for release in set.releases() {
        if release.slug != "notifications" {
            let bytes = segments
                .segment(&release.slug, &release.digest)
                .unwrap()
                .unwrap();
            fresh.insert(&release.slug, &release.digest, bytes);
        }
    }

    let module_set = set.content_key();
    let store = MemoryStore::default();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &fresh, &store, inner);

    let err = port.build_artifact(&module_set).await.unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("`notifications`"),
        "names the release: {message}"
    );
    assert!(
        message.contains("no deployer is wired"),
        "the inner refusal's text survives verbatim: {message}"
    );
    assert_eq!(
        counts.lock().expect("counting deployer poisoned").builds,
        [module_set.as_str()],
        "the build path was the fallback"
    );
}

/// A segment whose bytes fail their pin is refused outright: the deploy
/// stops with the reason and the build path is never substituted, because a
/// build would paper over a store that lies.
#[pollster::test]
async fn a_segment_failing_its_pin_through_the_port_is_refused_not_built() {
    let (catalog, segments) = six_modules();
    // Sabotage `cms`: the stored bytes no longer match the pinned digest.
    let wrong = pseudo_bytes(99, 4096);
    segments.insert("cms", &sha256_hex(&pseudo_bytes(4, 4096)), wrong);

    let set = resolve(&catalog, &["cms"]);
    let module_set = set.content_key();
    let store = MemoryStore::default();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &segments, &store, inner);

    let err = port.build_artifact(&module_set).await.unwrap_err();
    let message = err.to_string();
    assert!(message.contains("`cms`"), "names the slug: {message}");
    assert!(
        message.contains("refused to compose this set and did not fall back to a build"),
        "says it refused rather than built: {message}"
    );
    assert!(
        counts
            .lock()
            .expect("counting deployer poisoned")
            .builds
            .is_empty(),
        "a failing pin is never papered over with a build"
    );
}

/// A corrupt cache entry through the port is refused, not built. The
/// refusal is decided in the adapter — `link_pins` only returns the error
/// — so that is where the property has to hold: the deploy stops with the
/// reason and the inner build path is never substituted, because a build
/// would ship bytes the store corrupted.
#[pollster::test]
async fn a_corrupt_cache_entry_through_the_port_is_refused_not_built() {
    let (catalog, segments) = six_modules();
    let set = resolve(&catalog, &["email-signup"]);
    let module_set = set.content_key();

    // Warm an honest store first, so the next call is a hit — the only
    // way to reach the cache-verification code.
    let honest = MemoryStore::default();
    let warmer = LinkedArtifacts::new(
        CatalogPins(&catalog),
        inputs(),
        &segments,
        &honest,
        CountingDeployer::new(),
    );
    warmer.build_artifact(&module_set).await.unwrap();

    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let sabotaged = CorruptingStore(honest);
    let port = LinkedArtifacts::new(
        CatalogPins(&catalog),
        inputs(),
        &segments,
        &sabotaged,
        inner,
    );

    let err = port.build_artifact(&module_set).await.unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("does not match its recorded digest"),
        "the refusal names the corruption: {message}"
    );
    assert!(
        message.contains("refused to compose this set and did not fall back to a build"),
        "says it refused rather than built: {message}"
    );
    assert!(
        counts
            .lock()
            .expect("counting deployer poisoned")
            .builds
            .is_empty(),
        "an integrity failure is never papered over with a build"
    );
}

/// A set the pin source cannot pin falls back carrying the source's own
/// reason — here a catalog copy that has not caught up with the venture.
#[pollster::test]
async fn a_set_the_pin_source_cannot_pin_falls_back_carrying_that_source_s_reason() {
    let (mut catalog, segments) = six_modules();
    // The control plane's catalog copy has no `cms`.
    catalog.modules.retain(|m| m.slug != "cms");
    let module_set = "cms";
    let store = MemoryStore::default();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &segments, &store, inner);

    match CatalogPins(&catalog).pins(module_set) {
        Pins::Unavailable(reason) => {
            assert!(
                reason.contains("`cms` is not a module in the catalog"),
                "the resolver names the slug: {reason}"
            );
            let err = port.build_artifact(module_set).await.unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains(&reason),
                "the fallback carries the source's reason verbatim: {message}"
            );
            assert!(
                message.contains("no deployer is wired"),
                "the inner refusal's text survives verbatim: {message}"
            );
        }
        Pins::Published(_) => panic!("a catalog without `cms` cannot pin the set"),
    }
    assert_eq!(
        counts.lock().expect("counting deployer poisoned").builds,
        [module_set.to_owned()],
        "the build path was the fallback"
    );
}

/// Degenerate content keys pin nothing and panic nowhere: the empty key,
/// a trailing `+`, and a slug the catalog does not know are all
/// [`Pins::Unavailable`] with the resolver's reason — never a pin set,
/// which is what would matter if a malformed key could mint an artifact.
#[test]
fn degenerate_content_keys_are_unavailable_never_pinned() {
    let (catalog, _) = six_modules();
    for key in ["", "cms+", "no-such-module"] {
        match CatalogPins(&catalog).pins(key) {
            Pins::Unavailable(reason) => assert!(
                !reason.is_empty(),
                "the unavailability carries a reason for `{key}`: {reason}"
            ),
            Pins::Published(releases) => {
                panic!("`{key}` must not resolve to pins, got {releases:?}")
            }
        }
    }
}

/// The adapter exists for one step. The other six arrive at the inner
/// deployer unchanged — same argument list, nothing added.
#[pollster::test]
async fn the_other_six_steps_go_to_the_inner_deployer_unchanged() {
    let (catalog, segments) = six_modules();
    let store = MemoryStore::default();
    let inner = CountingDeployer::new();
    let counts = inner.handle();
    let port = LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &segments, &store, inner);

    port.ensure_database("tenant-1").await.unwrap();
    port.ensure_worker("tenant-1", "core+email-signup")
        .await
        .unwrap();
    port.apply_schema("tenant-1", "core+email-signup")
        .await
        .unwrap();
    port.seed_secrets("tenant-1").await.unwrap();
    port.bind_route("tenant-1", "venture.example.com")
        .await
        .unwrap();
    assert!(port.health_ok("venture.example.com").await.unwrap());

    let calls = counts.lock().expect("counting deployer poisoned");
    assert_eq!(calls.databases, ["tenant-1".to_owned()]);
    assert_eq!(
        calls.workers,
        [("tenant-1".to_owned(), "core+email-signup".to_owned())]
    );
    assert_eq!(
        calls.schemas,
        [("tenant-1".to_owned(), "core+email-signup".to_owned())]
    );
    assert_eq!(calls.secrets, ["tenant-1".to_owned()]);
    assert_eq!(calls.routes, ["venture.example.com".to_owned()]);
    assert_eq!(calls.healths, ["venture.example.com".to_owned()]);
    assert!(
        calls.builds.is_empty(),
        "the artifact step is the only one this adapter touches"
    );
}

/// The measurement behind the artifact-step rows of
/// `docs/control-plane/LINKER.md`, taken where the step actually runs:
/// through provisioning's [`Deployer`] port. Same workload as
/// `measured_cold_compose_and_cache_hit` (six synthetic segments, 4 KiB
/// each), same sample counts, same printed shape, so the lines sit beside
/// each other; every cold sample composes into a fresh store so every one
/// really is cold, and the adapter is rebuilt per sample because the
/// store it owns is what makes a sample cold. Asserts only the
/// structural facts the numbers depend on — the build path was never
/// reached, cold samples fetched one segment per module and hit samples
/// fetched none — because wall-clock assertions would flake CI; the doc
/// carries the numbers.
#[pollster::test]
async fn measured_artifact_step_through_the_port() {
    const COLD_SAMPLES: usize = 100;
    const HIT_SAMPLES: usize = 200;

    let (catalog, segments) = six_modules();
    let set = resolve(
        &catalog,
        &[
            "email-signup",
            "waitlist",
            "cms",
            "notifications",
            "privacy",
        ],
    );
    let module_set = set.content_key();

    // The adapter owns its inner deployer, so one is built per port; they
    // all share this one ledger.
    #[allow(clippy::disallowed_types)] // test fixture, not request state
    let counts = Arc::new(Mutex::new(Calls::default()));
    let inner = || CountingDeployer {
        calls: Arc::clone(&counts),
    };

    // One untimed cold compose to page the resolver in, on its own
    // throwaway store.
    let warmup = LinkedArtifacts::new(
        CatalogPins(&catalog),
        inputs(),
        &segments,
        MemoryStore::default(),
        inner(),
    );
    warmup.build_artifact(&module_set).await.unwrap();

    // Cold: a fresh store per sample, so every sample really is cold.
    let mut cold = Vec::with_capacity(COLD_SAMPLES);
    for _ in 0..COLD_SAMPLES {
        let port = LinkedArtifacts::new(
            CatalogPins(&catalog),
            inputs(),
            &segments,
            MemoryStore::default(),
            inner(),
        );
        let start = std::time::Instant::now();
        port.build_artifact(&module_set).await.unwrap();
        cold.push(start.elapsed());
    }

    // Hit: one store warmed once, then hits only.
    let store = MemoryStore::default();
    let warmer = LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &segments, &store, inner());
    warmer.build_artifact(&module_set).await.unwrap();
    let mut hit = Vec::with_capacity(HIT_SAMPLES);
    for _ in 0..HIT_SAMPLES {
        let port =
            LinkedArtifacts::new(CatalogPins(&catalog), inputs(), &segments, &store, inner());
        let start = std::time::Instant::now();
        port.build_artifact(&module_set).await.unwrap();
        hit.push(start.elapsed());
    }

    assert!(
        counts
            .lock()
            .expect("counting deployer poisoned")
            .builds
            .is_empty(),
        "every run was served by the linker; the build path was never reached"
    );
    // The warm-up, every cold sample, and the hit store's one warm-up
    // compose each fetched one segment per module; the hits themselves
    // fetched none.
    assert_eq!(
        segments.fetches(),
        (2 + COLD_SAMPLES) * set.releases().len(),
        "cold samples fetched one segment per module and hits fetched none"
    );

    // The port answers `Ok(())` and no more, so the bundle's size is
    // measured by composing the same set directly.
    let composed = link(&set, &inputs(), &segments, &MemoryStore::default()).unwrap();
    let payload: usize = set
        .releases()
        .iter()
        .map(|r| segments.segment(&r.slug, &r.digest).unwrap().unwrap().len())
        .sum();
    let cold = Summary::new(cold);
    let hit = Summary::new(hit);
    println!(
        "cold compose: n={} min={:?} p50={:?} p99={:?} max={:?} \
         (a fresh store per sample; {} segments, {payload} bytes, bundle {} bytes)\n\
         hit:          n={} min={:?} p50={:?} p99={:?} max={:?}",
        cold.n,
        cold.min,
        cold.p50,
        cold.p99,
        cold.max,
        set.releases().len(),
        composed.bytes.len(),
        hit.n,
        hit.min,
        hit.p50,
        hit.p99,
        hit.max,
    );
}

/// The measurement behind the "what the wiring costs today" figure in
/// `docs/control-plane/LINKER.md`: the artifact step every real set takes
/// right now. The pins are the catalog's all-zero placeholders — exactly
/// what the control plane holds until release stamping — so the adapter
/// refuses to compose and hands the set to the build path with the reason
/// attached, which is the whole cost: there is no segment to fetch and no
/// bundle to store, and with placeholders every call takes this same path.
/// Same [`Deployer`] port as `measured_artifact_step_through_the_port`,
/// 200 samples like its hit path, and the same structural assertions per
/// sample — the reason names the placeholder, the inner refusal survives
/// verbatim, the build path was reached — never wall-clock; the doc
/// carries the numbers.
#[pollster::test]
async fn measured_placeholder_fallback_the_control_plane_takes_today() {
    const SAMPLES: usize = 200;

    let catalog = builtin();
    #[allow(clippy::disallowed_types)] // test fixture, not request state
    let counts = Arc::new(Mutex::new(Calls::default()));
    let port = LinkedArtifacts::new(
        CatalogPins(&catalog),
        inputs(),
        UnpublishedSegments,
        NoStore,
        CountingDeployer {
            calls: Arc::clone(&counts),
        },
    );

    // One untimed warm-up, as in the other measured tests; its reason is
    // also the one the doc describes, so it is checked in full here.
    let warmup = port
        .build_artifact("email-signup")
        .await
        .expect_err("nothing is published, so the set falls back to the build path");
    let message = warmup.to_string();
    assert!(
        message.contains("all-zero placeholder"),
        "the reason names the placeholder: {message}"
    );
    assert!(
        message.contains("no deployer is wired"),
        "the inner refusal's text survives verbatim: {message}"
    );
    let reason_bytes = message.len();

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = std::time::Instant::now();
        let err = port
            .build_artifact("email-signup")
            .await
            .expect_err("nothing is published, so the set falls back to the build path");
        samples.push(start.elapsed());
        let message = err.to_string();
        assert!(
            message.contains("all-zero placeholder"),
            "the reason names the placeholder: {message}"
        );
        assert!(
            message.contains("no deployer is wired"),
            "the inner refusal's text survives verbatim: {message}"
        );
    }

    assert_eq!(
        counts.lock().expect("counting deployer poisoned").builds,
        vec!["email-signup".to_owned(); 1 + SAMPLES],
        "every call, warm-up included, took the build path"
    );

    let summary = Summary::new(samples);
    println!(
        "placeholder fallback: n={} min={:?} p50={:?} p99={:?} max={:?} \
         (the recorded reason is {reason_bytes} bytes)",
        summary.n, summary.min, summary.p50, summary.p99, summary.max,
    );
}
