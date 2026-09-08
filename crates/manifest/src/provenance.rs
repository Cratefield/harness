//! Build provenance and the build-service environment contract (issue #142).
//!
//! Two halves, deliberately kept apart:
//!
//! - [`BuildEnvironmentAttestation`] is the *contract* a build service
//!   must satisfy and attest to before a non-coder artifact exists: the
//!   manifest is data and resolution is policy, but neither constrains
//!   what the *compiler* fetches. A pin the catalog approved is only
//!   real if the build ran in a disposable, network-restricted,
//!   credential-free environment and consumed exactly that digest. The
//!   attestation is a typed, checkable statement of that; it is **not**
//!   self-enforcing — a local `fz build` can set the environment
//!   variables, so an attestation is only meaningful on the service's
//!   own builder identity, which is control-plane infrastructure and
//!   out of this repo. This crate's job is to make the claim itemized
//!   and checkable rather than vibes, and to refuse to write a
//!   provenance record that contradicts it.
//! - [`Provenance`] is what a finished build records: the exact
//!   reviewed releases resolution pinned (issue #142 gate), a per-file
//!   content digest of the generated artifact, the composition hash,
//!   builder identity, and the attestation (or an explicit `null` for
//!   unsanctioned local builds — an honest gap, never a fake pass).
//!   [`Provenance::verify_against`] recomputes everything from the
//!   artifact on disk, so a swapped file, a drifted composition, or a
//!   provenance that names modules the artifact does not contain all
//!   fail closed.
//!
//! This module is wasm-clean like the rest of the crate: no clock, no
//! environment reads, no filesystem. `built_at` is supplied by the
//! caller (the CLI takes it from an explicit flag/env var; the build
//! service passes its own). Absent is a valid state and serializes as
//! `null` — the CLI never invents a timestamp, because there is no
//! portable clock here and a fabricated one is worse than none.

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

use crate::catalog::{ModuleSet, PinnedRelease, is_sha256_digest};
use crate::generate::{GeneratedVenture, composition_hash_of};

/// The schema tag of a provenance record. Verification refuses anything
/// that does not carry the one shape it understands: a silent read of a
/// future format would let an unknown field quietly mean nothing.
pub const PROVENANCE_SCHEMA: &str = "fz-provenance/1";

/// The all-zero `sha256:` value the built-in catalog ships as a visible
/// placeholder until CI stamps real release digests (see
/// [`crate::catalog::builtin`]). A sanctioned build must never be
/// pinned to it.
#[must_use]
pub fn is_placeholder_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|c| c == '0'))
}

/// The content digest of one generated file, as a `sha256:<64 hex>`
/// string — the same shape [`crate::catalog::is_sha256_digest`] accepts.
#[must_use]
pub fn file_digest(contents: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contents.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in &digest {
        let _ = std::fmt::write(&mut hex, format_args!("{byte:02x}"));
    }
    hex
}

/// Resource ceilings a sanctioned build environment must declare it
/// enforced (issue #142): an unbounded compile is a denial-of-service
/// against whatever hosts it. Values are strings because the enforcing
/// substrate is the service's (container/VM), and this contract only
/// requires the attestation to state a limit, in whatever units that
/// substrate uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResourceLimits {
    pub wall_clock: String,
    pub memory: String,
    pub disk: String,
}

/// The environment a non-coder build must have run in, as attested by
/// the builder (issue #142). Every field is a hard check:
/// [`BuildEnvironmentAttestation::check`] lists the violations it can
/// see, and a provenance record refuses to embed an attestation that
/// fails. The attestation's own content digest lets a verifier pin
/// *which* environment document was claimed, so two builds on the same
/// builder identity still say whether they ran under the same rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
// Four bools, and each one is a *separate* hard check in
// [`Self::check`]: an enum could not say "deploy credentials withheld
// but the production key present", which is exactly the distinction
// that makes a build-service build honest and a dev machine's not.
#[allow(clippy::struct_excessive_bools)]
pub struct BuildEnvironmentAttestation {
    /// Digest of the sandbox image (or equivalent immutable build
    /// environment) the compile ran in, `sha256:<64 hex>`.
    pub sandbox_digest: String,
    /// Whether the environment is disposable: destroyed after one
    /// build, never reused, so nothing from a previous compile can
    /// leak into this one.
    pub disposable: bool,
    /// Whether the source checkout was scoped to this workspace's
    /// inputs only. Anything broader lets one tenant's build read
    /// another's code.
    pub workspace_scoped: bool,
    /// The egress posture the compile ran under. A build must be able
    /// to fetch only its pinned, digested inputs — `"deny-all"` or
    /// `"registry-allowlist"`; anything else (including `"open"`) is a
    /// violation, because arbitrary egress is how a poisoned pin
    /// phones home.
    pub network_egress: String,
    /// Whether the build service attests it withheld deploy
    /// credentials from this build (issue #142). True means the
    /// attester checked its own environment and found none; it is the
    /// service's statement about its service, not a sandbox claim —
    /// see this module's header about what a local build's `true` is
    /// worth.
    pub deploy_credentials_withheld: bool,
    /// Whether the build ran with the platform's **production** KMS
    /// key absent, not merely a different tenant's (issue #142). A
    /// compile that can call the production KEK can unwrap any
    /// tenant's secrets without ever printing one, so absence of
    /// prod-key access is the property; absence of *a* key is not.
    pub production_key_absent: bool,
    pub limits: ResourceLimits,
}

impl BuildEnvironmentAttestation {
    /// Every way this attestation falls short of the contract, itemized
    /// (issue #142). An empty vec is the only pass; there is no
    /// severity, because each item is a way a supply-chain build can
    /// be silently compromised.
    #[must_use]
    pub fn check(&self) -> Vec<&'static str> {
        let mut violations = Vec::new();
        if !is_sha256_digest(&self.sandbox_digest) || is_placeholder_digest(&self.sandbox_digest) {
            violations.push("sandbox digest is not a real `sha256:` content address");
        }
        if !self.disposable {
            violations.push("environment is not disposable (reused state leaks across builds)");
        }
        if !self.workspace_scoped {
            violations.push("checkout is not workspace-scoped (cross-tenant source reads)");
        }
        if !matches!(
            self.network_egress.as_str(),
            "deny-all" | "registry-allowlist"
        ) {
            violations.push("network egress is unrestricted");
        }
        if !self.deploy_credentials_withheld {
            violations.push("deploy credentials were present to the build");
        }
        if !self.production_key_absent {
            violations.push("the production KMS key was reachable from the build");
        }
        for (name, limit) in [
            ("wall-clock", &self.limits.wall_clock),
            ("memory", &self.limits.memory),
            ("disk", &self.limits.disk),
        ] {
            if limit.trim().is_empty() {
                violations.push(match name {
                    "wall-clock" => "no wall-clock limit declared",
                    "memory" => "no memory limit declared",
                    _ => "no disk limit declared",
                });
            }
        }
        violations
    }

    /// The content digest of this attestation itself, for verifiers to
    /// compare which environment document a build claimed, without
    /// re-reading the whole record.
    #[must_use]
    pub fn attestation_digest(&self) -> String {
        file_digest(&self.to_json())
    }

    /// Canonical JSON of the attestation (compact, key order fixed by
    /// the struct). Both the record and the digest go through this one
    /// serializer so a digest computed here always matches one
    /// recomputed from a parsed copy.
    ///
    /// # Panics
    ///
    /// Never: every field is a plain string/bool, and `serde_json` only
    /// errors on non-string map keys, of which there are none.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("attestation JSON is infallible")
    }

    /// Parse an attestation from its JSON.
    ///
    /// # Errors
    ///
    /// The serde error text if the JSON is not this shape.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
}

/// Why an environment attestation cannot be trusted for a non-coder
/// build (issue #142). Carries every violation at once so the operator
/// fixes the whole environment, not one variable at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildEnvViolation(pub Vec<&'static str>);

impl std::fmt::Display for BuildEnvViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "build environment fails the issue #142 contract: {}",
            self.0.join("; ")
        )
    }
}

impl std::error::Error for BuildEnvViolation {}

/// One file recorded by provenance: path plus content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProvenanceFile {
    pub path: String,
    pub digest: String,
}

/// What a build produced and under what environment (issue #142).
/// Written by `fz build` as `provenance.json` beside the artifact and
/// re-checked by any verifier with [`Provenance::verify_against`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Provenance {
    /// Format tag; must be [`PROVENANCE_SCHEMA`] for records this code
    /// will verify.
    pub schema: String,
    pub venture: String,
    /// The module-set content key the artifact was built for (harness
    /// ADR 0009).
    pub module_set: String,
    /// The exact reviewed releases resolution pinned, one per module,
    /// in [`ModuleSet::slugs`] order (issue #142).
    pub releases: Vec<PinnedRelease>,
    pub composition_hash: String,
    pub files: Vec<ProvenanceFile>,
    /// Caller-supplied timestamp, RFC 3339 text. `None` serializes as
    /// `null`: no clock was available and none was invented.
    pub built_at: Option<String>,
    /// Who ran the build (builder identity). On the service this names
    /// the fleet that made the attestation meaningful; locally it is
    /// whatever the operator passed, and a verifier should weight it
    /// accordingly.
    pub builder: String,
    /// The environment the build claims to have run under, or `null`
    /// for an unsanctioned local build — an explicit gap, never a
    /// stubbed pass (issue #142 honesty rule).
    pub attestation: Option<BuildEnvironmentAttestation>,
}

/// Why a provenance record does not hold up (issue #142). Every variant
/// is a way the artifact and its paper disagree; all are hard failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// A file on disk hashes to something other than what the record
    /// says. Either the artifact changed after the build, or the build
    /// lied.
    FileDigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    /// The record's file list and the artifact's files are not the same
    /// set (extra, missing, or reordered).
    FileListMismatch {
        record: Vec<String>,
        artifact: Vec<String>,
    },
    /// The recomputed composition hash does not match the recorded one.
    CompositionMismatch { expected: String, actual: String },
    /// The record names a different module set than the artifact.
    ModuleSetMismatch { expected: String, actual: String },
    /// The record names a different venture than the artifact.
    VentureMismatch { expected: String, actual: String },
    /// A sanctioned build (attestation present) was pinned to the
    /// all-zero placeholder digest — CI release stamping has not run
    /// for this version, so there is no real content address to
    /// verify against (issue #142).
    UnstampedPin(String),
    /// The record was built from an environment that fails the
    /// attestation contract; the itemized reasons ride along.
    Environment(BuildEnvViolation),
    /// The JSON is not a record this code understands.
    BadRecord(String),
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvenanceError::FileDigestMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "`{path}` hashes to `{actual}`, but provenance records `{expected}` — the \
                 artifact does not match the build that claims to have produced it"
            ),
            ProvenanceError::FileListMismatch { record, artifact } => write!(
                f,
                "provenance records {} files ({}), the artifact has {} ({})",
                record.len(),
                record.join(", "),
                artifact.len(),
                artifact.join(", "),
            ),
            ProvenanceError::CompositionMismatch { expected, actual } => write!(
                f,
                "composition hash mismatch: provenance records `{expected}`, recomputed `{actual}`"
            ),
            ProvenanceError::ModuleSetMismatch { expected, actual } => write!(
                f,
                "provenance names module set `{expected}`, the artifact is `{actual}`"
            ),
            ProvenanceError::VentureMismatch { expected, actual } => write!(
                f,
                "provenance names venture `{expected}`, the artifact is `{actual}`"
            ),
            ProvenanceError::UnstampedPin(slug) => write!(
                f,
                "`{slug}` is pinned to the placeholder digest; a sanctioned build refuses \
                 until release stamping produces a real content address"
            ),
            ProvenanceError::Environment(v) => write!(f, "{v}"),
            ProvenanceError::BadRecord(why) => write!(f, "provenance record is unreadable: {why}"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

impl Provenance {
    /// Record what this build produced.
    ///
    /// Refuses, rather than records, a contradiction (issue #142): an
    /// attestation that fails [`BuildEnvironmentAttestation::check`], or
    /// a sanctioned build pinned to a placeholder digest. A local build
    /// passes `attestation: None` and gets an honest unsanctioned
    /// record.
    ///
    /// # Errors
    ///
    /// See [`ProvenanceError`] — `Environment` or `UnstampedPin` here.
    pub fn record(
        artifact: &GeneratedVenture,
        module_set: &ModuleSet,
        builder: &str,
        built_at: Option<&str>,
        attestation: Option<BuildEnvironmentAttestation>,
    ) -> Result<Self, ProvenanceError> {
        if let Some(env) = &attestation {
            let violations = env.check();
            if !violations.is_empty() {
                return Err(ProvenanceError::Environment(BuildEnvViolation(violations)));
            }
            for release in module_set.releases() {
                if is_placeholder_digest(&release.digest) {
                    return Err(ProvenanceError::UnstampedPin(release.slug.clone()));
                }
            }
        }
        Ok(Self {
            schema: PROVENANCE_SCHEMA.to_owned(),
            venture: artifact.name.clone(),
            module_set: artifact.content_key.clone(),
            releases: module_set.releases().to_vec(),
            composition_hash: artifact.composition_hash.clone(),
            files: artifact
                .files
                .iter()
                .map(|file| ProvenanceFile {
                    path: file.path.clone(),
                    digest: file_digest(&file.contents),
                })
                .collect(),
            built_at: built_at.map(str::to_owned),
            builder: builder.to_owned(),
            attestation,
        })
    }

    /// Serialize to pretty JSON for writing as `provenance.json`.
    ///
    /// # Panics
    ///
    /// Never: every field is a plain string, number, bool, or a
    /// sequence thereof; `serde_json` only errors on non-string map keys.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("provenance JSON is infallible")
    }

    /// Parse a provenance record, refusing anything that is not the one
    /// schema this code verifies.
    ///
    /// # Errors
    ///
    /// See [`ProvenanceError`] — `BadRecord` for wrong schema or junk.
    pub fn from_json(json: &str) -> Result<Self, ProvenanceError> {
        let record: Self =
            serde_json::from_str(json).map_err(|e| ProvenanceError::BadRecord(e.to_string()))?;
        if record.schema != PROVENANCE_SCHEMA {
            return Err(ProvenanceError::BadRecord(format!(
                "schema is `{}`, this build verifies `{}`",
                record.schema, PROVENANCE_SCHEMA
            )));
        }
        Ok(record)
    }

    /// Check a recorded provenance against the artifact it claims to
    /// describe (issue #142): venture and module set agree, every
    /// recorded file digest recomputes from the file on the generated
    /// artifact, and the composition hash the artifact itself carries
    /// matches both the record and a fresh recomputation. The record
    /// must carry the expected schema; use [`Self::from_json`] to load.
    ///
    /// Note what this does *not* claim: it proves the artifact and the
    /// paper agree with each other. Whether the paper is true (the
    /// attestation, the builder's identity) is a trust judgment about
    /// who wrote it — the record never certifies itself.
    ///
    /// # Errors
    ///
    /// See [`ProvenanceError`] — any digest, list, or identity
    /// disagreement.
    pub fn verify_against(&self, artifact: &GeneratedVenture) -> Result<(), ProvenanceError> {
        if self.venture != artifact.name {
            return Err(ProvenanceError::VentureMismatch {
                expected: self.venture.clone(),
                actual: artifact.name.clone(),
            });
        }
        if self.module_set != artifact.content_key {
            return Err(ProvenanceError::ModuleSetMismatch {
                expected: self.module_set.clone(),
                actual: artifact.content_key.clone(),
            });
        }
        let record_paths: Vec<String> = self.files.iter().map(|f| f.path.clone()).collect();
        let artifact_paths: Vec<String> = artifact.files.iter().map(|f| f.path.clone()).collect();
        if record_paths != artifact_paths {
            return Err(ProvenanceError::FileListMismatch {
                record: record_paths,
                artifact: artifact_paths,
            });
        }
        for (record, file) in self.files.iter().zip(&artifact.files) {
            let actual = file_digest(&file.contents);
            if record.digest != actual {
                return Err(ProvenanceError::FileDigestMismatch {
                    path: file.path.clone(),
                    expected: record.digest.clone(),
                    actual,
                });
            }
        }
        let recomputed = composition_hash_of(&artifact.files);
        if self.composition_hash != recomputed {
            return Err(ProvenanceError::CompositionMismatch {
                expected: self.composition_hash.clone(),
                actual: recomputed,
            });
        }
        if artifact.composition_hash != recomputed {
            return Err(ProvenanceError::CompositionMismatch {
                expected: artifact.composition_hash.clone(),
                actual: recomputed,
            });
        }
        Ok(())
    }
}
