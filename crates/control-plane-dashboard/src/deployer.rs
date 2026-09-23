//! The deployer the dashboard's provisioning routes hand the engine.
//!
//! Provisioning's [`Deployer`] port is seven steps, and the artifact step
//! is the only one anything exists for yet. [`current`] hands the engine
//! [`LinkedArtifacts`]: the linker (issue #159) resolves the venture's
//! module-set key against the control plane's own copy of the catalog and
//! composes the artifact from pinned releases when it can, falling back to
//! the build path — provisioning's [`Unwired`] — with the reason attached
//! when it cannot. Every other step is [`Unwired`]'s verbatim, because no
//! adapter talks to Cloudflare yet (#141).
//!
//! [`Deployer`]: cratefield_provisioning::Deployer
//!
//! Today nothing composes: every pin in the curated catalog is the
//! all-zero placeholder digest until release stamping lands, so every real
//! set falls back to the build path, and the reason the ledger records is
//! that no release digest is stamped. The wiring is still the point — the
//! day segments are published, the decisions in this file are the ones
//! every run goes through, and a configuration-only change finds the
//! composed bundle instead of a build.

use cratefield_core::HARNESS_API;
use cratefield_linker::{
    LinkInputs, LinkedArtifacts, NoStore, PinSource, PinnedRelease, Pins, UnpublishedSegments,
};
use cratefield_provisioning::Unwired;

/// The rustc version named in the artifact's build key. The key is a
/// function of the rustc version (issue #59), so it must describe whatever
/// toolchain produced the segments a bundle composes. Nothing produces
/// segments yet, so the control plane names the channel this repository
/// pins in `rust-toolchain.toml` — a test holds the two together so they
/// cannot drift silently. When a real segment store lands, this must come
/// from the store's own record of the toolchain — a segment compiled by a
/// different rustc is a different artifact — not from a constant here.
pub(crate) const TOOLCHAIN: &str = "rustc 1.98.1";

/// A [`PinSource`] over the control plane's own copy of the catalog: the
/// curated set, resolved the way the screens resolve a selection, with the
/// `+`-joined module-set content key split back into slugs. The two catalog
/// crates' types and resolvers are a deliberate duplicate (issue #5) —
/// `cratefield-catalog` is what the screens speak, `cratefield-manifest` is
/// what the linker's pins are typed as — and this field-for-field mapping
/// is the seam between them. The module list and pins themselves are not
/// duplicated: `curated()` takes them from `cratefield_manifest::builtin()`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CuratedPins;

impl PinSource for CuratedPins {
    fn pins(&self, module_set: &str) -> Pins {
        let slugs: Vec<&str> = module_set.split('+').collect();
        match cratefield_catalog::curated().resolve(&slugs) {
            Ok(set) => Pins::Published(
                set.releases()
                    .iter()
                    .map(|release| PinnedRelease {
                        slug: release.slug.clone(),
                        version: release.version.clone(),
                        digest: release.digest.clone(),
                    })
                    .collect(),
            ),
            Err(err) => Pins::Unavailable(format!(
                "module set `{module_set}` does not resolve against the curated catalog: {err}"
            )),
        }
    }
}

/// The deployer the provisioning routes hand the engine. The artifact step
/// goes through the linker; every other step still goes to [`Unwired`],
/// because no adapter talks to Cloudflare yet (#141). With
/// [`UnpublishedSegments`] every real set falls back to the build path
/// today — the reason being that no release digest is stamped — and that
/// reason is what the ledger records, ahead of the build path's own
/// refusal.
///
/// The return type is the concrete composition, deliberately: the
/// [`Deployer`] port is async-fn-in-trait, so an `impl Deployer` return
/// gives axum's `Handler` bound (which wants a `Send` future) nothing to
/// hold onto, and every route using this fails to compile.
#[must_use]
pub(crate) fn current() -> LinkedArtifacts<CuratedPins, UnpublishedSegments, NoStore, Unwired> {
    LinkedArtifacts::new(
        CuratedPins,
        LinkInputs::release(HARNESS_API, TOOLCHAIN),
        UnpublishedSegments,
        NoStore,
        Unwired,
    )
}

#[cfg(test)]
mod tests {
    use super::{CuratedPins, TOOLCHAIN};
    use cratefield_linker::{PinSource, Pins};

    /// `rust-toolchain.toml`, read at compile time so the drift test below
    /// cannot be separated from the file it reads.
    const RUST_TOOLCHAIN: &str = include_str!("../../../rust-toolchain.toml");

    /// The seam between the two catalog crates' types (issue #5's
    /// deliberate duplicate; the module list itself is `builtin()`'s)
    /// carries every module of a curated set across intact — slug,
    /// version and digest, field for field — and every digest it
    /// hands the linker is the all-zero placeholder, which is exactly why
    /// the adapter refuses to compose and falls back to the build path.
    /// The reference is resolved from the content key, because the key is
    /// what travels: the screens carry `+`-joined slugs, and resolution
    /// order legitimately differs by pick order.
    #[test]
    fn curated_pins_map_the_catalog_s_pins_onto_the_linker_s_pin_type() {
        for selected in [
            vec!["cms"],
            vec!["email-signup", "waitlist", "notifications"],
        ] {
            let key = cratefield_catalog::curated()
                .resolve(&selected)
                .expect("the curated catalog offers this selection")
                .content_key();
            let resolved = cratefield_catalog::curated()
                .resolve(&key.split('+').collect::<Vec<_>>())
                .expect("the content key resolves against the same catalog");
            match CuratedPins.pins(&key) {
                Pins::Published(releases) => {
                    assert_eq!(
                        releases.len(),
                        resolved.releases().len(),
                        "one pin per resolved module of `{key}`: {releases:?}"
                    );
                    for (mapped, source) in releases.iter().zip(resolved.releases()) {
                        assert_eq!(mapped.slug, source.slug, "the same slug: {key}");
                        assert_eq!(mapped.version, source.version, "the same version: {key}");
                        assert_eq!(mapped.digest, source.digest, "the same digest: {key}");
                        let hex = mapped
                            .digest
                            .strip_prefix("sha256:")
                            .expect("a pin is a sha256 content address");
                        assert!(
                            hex.chars().all(|c| c == '0'),
                            "every pin the seam hands the linker is the all-zero \
                             placeholder the adapter then refuses to compose: {mapped:?}"
                        );
                    }
                }
                Pins::Unavailable(reason) => {
                    panic!("the curated catalog resolves `{key}`, so it pins: {reason}")
                }
            }
        }
    }

    /// The build key names a rustc version, so [`TOOLCHAIN`] must describe
    /// the toolchain this repository builds with. The channel is parsed out
    /// of `rust-toolchain.toml` — included at compile time — and held
    /// against the constant as an exact match, so the two cannot drift in
    /// either direction: a constant bumped past the file fails this just as
    /// a file bumped past the constant does.
    #[test]
    fn the_toolchain_constant_names_the_channel_rust_toolchain_toml_pins() {
        let channel = RUST_TOOLCHAIN
            .lines()
            .find_map(|line| {
                let line = line.trim();
                line.strip_prefix("channel = \"")
                    .and_then(|rest| rest.strip_suffix('"'))
            })
            .expect("rust-toolchain.toml pins a channel");
        let named = TOOLCHAIN
            .strip_prefix("rustc ")
            .expect("the constant names a rustc version");
        assert_eq!(
            named, channel,
            "the build key names `{TOOLCHAIN}`, but rust-toolchain.toml pins \
             `rustc {channel}`; the segments a store serves were produced by one toolchain \
             and the key must say exactly which"
        );
    }

    /// Degenerate content keys pin nothing and panic nowhere — and this is
    /// the production seam, where a malformed key arriving from the
    /// screens would otherwise be able to mint a pin set. The empty key, a
    /// trailing `+`, and a slug the curated catalog does not know are all
    /// `Pins::Unavailable` carrying the resolver's reason, which is what
    /// sends them down the fallback ladder instead.
    #[test]
    fn degenerate_content_keys_are_unavailable_never_pinned() {
        for key in ["", "cms+", "no-such-module"] {
            match CuratedPins.pins(key) {
                Pins::Unavailable(reason) => assert!(
                    reason.contains("does not resolve against the curated catalog"),
                    "the unavailability says where it came from, for `{key}`: {reason}"
                ),
                Pins::Published(releases) => {
                    panic!("`{key}` must not resolve to pins, got {releases:?}")
                }
            }
        }
    }
}
