//! The tenant a request belongs to, and the statuses the control
//! database's registry carries (RECONCILIATION.md §6, ADR 0008,
//! TENANT-ROUTING.md).
//!
//! [`TenantId`] and [`Tenant`] are nameable everywhere and constructible
//! only here. That is the whole isolation argument: a module cannot ask
//! the registry for a neighbour's pool by writing a different string,
//! because it cannot write a [`TenantId`] at all. Same shape as
//! `HarnessOnly` in the secrets crate (#39), and for the same reason —
//! the type is the boundary, not a convention about how to call a
//! function.

/// A tenant database's reconciliation status.
///
/// Serializes as the registry's own text (`"active"`), not the variant
/// name, so a structured log field and a registry row cannot drift apart.
/// `round_trips_through_the_registry_text` and
/// `serializes_as_the_registry_text` together pin that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    /// Reconciled and serving.
    Active,
    /// Registered, reconciliation not yet succeeded.
    Provisioning,
    /// The last reconciliation failed: requests answer
    /// `503 tenant-degraded` until a boot succeeds.
    Degraded,
}

impl TenantStatus {
    /// The registry's text form, lowercase and stable.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Provisioning => "provisioning",
            Self::Degraded => "degraded",
        }
    }

    /// Parses the registry's text form; anything else (a future version
    /// wrote a status this binary does not know) reads as
    /// [`TenantStatus::Degraded`] — refuse, do not guess.
    #[must_use]
    pub fn parse(status: &str) -> Self {
        match status {
            "active" => Self::Active,
            "provisioning" => Self::Provisioning,
            _ => Self::Degraded,
        }
    }
}

impl std::fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A tenant's key in the control database's registry.
///
/// Not `String`, and not constructible outside core:
///
/// ```compile_fail
/// use cratefield_core::TenantId;
/// // The field is private: module code cannot name a tenant.
/// let _id = TenantId("someone-elses-tenant".to_owned());
/// ```
///
/// Naming the type is fine, which keeps signatures writable:
///
/// ```
/// use cratefield_core::TenantId;
/// fn takes_id(_id: &TenantId) {}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct TenantId(String);

impl TenantId {
    /// Minted from a registry row. `pub(crate)` on purpose — see the
    /// module docs.
    pub(crate) fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The tenant a request belongs to. Immutable, and built only by core's
/// resolution layer from a registry row — never from a header, a path
/// segment, or module code.
///
/// `Clone` because a request carries it into deferred work. Deliberately
/// **not** `Deserialize`: the threat is an identity read back in from an
/// attacker-supplied body, not one written out, so `Serialize` is fine
/// and wanted — a tenant id is a structured log field.
///
/// ```compile_fail
/// use cratefield_core::{Tenant, TenantStatus};
/// // No public constructor, so a handler cannot conjure a neighbour.
/// let _t = Tenant::new("other", TenantStatus::Active);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Tenant {
    id: TenantId,
    status: TenantStatus,
}

impl Tenant {
    pub(crate) fn new(id: impl Into<String>, status: TenantStatus) -> Self {
        Self {
            id: TenantId::new(id),
            status,
        }
    }

    #[must_use]
    pub fn id(&self) -> &TenantId {
        &self.id
    }

    #[must_use]
    pub fn status(&self) -> TenantStatus {
        self.status
    }

    /// Mints a tenant **for tests only**, behind the `test-support`
    /// feature.
    ///
    /// The private constructor is what stops a module naming a
    /// neighbour, and it also stops any crate outside core from
    /// constructing the `&Tenant` a [`TenantDatabases`] impl is handed —
    /// so a pool registry written in an adapter could not be tested
    /// against a real one at all. That is a worse outcome than an
    /// opt-in escape hatch.
    ///
    /// Opt-in is the point: a crate that wants this must name
    /// `features = ["test-support"]` in its `Cargo.toml`, which is
    /// visible in review, and a `dev-dependencies` entry keeps it out of
    /// the published graph entirely.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test(id: impl Into<String>, status: TenantStatus) -> Self {
        Self::new(id, status)
    }
}

/// What a deployment's registry says about a host.
///
/// The design sketch had three arms — `Found(Tenant)`, `Unknown`,
/// `Degraded(TenantId)` — but a `Tenant` already carries its status, so
/// the third was the same fact twice and two places to keep in step. It
/// also could not work: a `ResolveTenant` impl lives in a runtime crate,
/// and if the arm carried a `Tenant` the constructor would have to be
/// `pub`, which is exactly what §3 wants to avoid. So the trait reports
/// what the registry said and **core mints the [`Tenant`]**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A registry row for this host.
    Found {
        /// The row's primary key.
        id: String,
        /// The row's status, parsed fail-closed by
        /// [`TenantStatus::parse`].
        status: TenantStatus,
    },
    /// No row for this host: `404 unknown-tenant`.
    Unknown,
}

impl Resolution {
    /// The tenant a request may proceed with, or the problem that refuses
    /// it.
    ///
    /// Only [`TenantStatus::Active`] serves. `Provisioning` is refused
    /// with the same `503 tenant-degraded` as `Degraded`: it means
    /// registered-but-not-yet-reconciled, so its schema is not known to
    /// match the code, which is the condition the refusal exists for. One
    /// slug rather than two because the caller's situation is identical —
    /// come back later — and the operator learns which from the registry,
    /// not from the response.
    pub(crate) fn admit(self) -> Result<Tenant, &'static crate::problems::ProblemDef> {
        match self {
            Self::Found { id, status } if status == TenantStatus::Active => {
                Ok(Tenant::new(id, status))
            }
            Self::Found { .. } => Err(&crate::problems::SLUGS.tenant_degraded),
            Self::Unknown => Err(&crate::problems::SLUGS.unknown_tenant),
        }
    }
}

/// How a deployment turns a request's host into a tenant.
///
/// A trait so a deployment that must resolve by something else can, and
/// so tests resolve without DNS. Host is the harness's answer — it is
/// established before any tenant state is consulted, is already validated
/// (#129), and is what the registry is keyed on anyway. A caller-supplied
/// header is refused as policy: a deployment that got
/// `TRUSTED_PROXY_HEADERS` wrong would let any caller name any tenant,
/// and the blast radius of that mistake is every tenant's data
/// (TENANT-ROUTING.md §3).
pub trait ResolveTenant: Send + Sync {
    /// The registry's answer for `host`. Implementations must not block
    /// on a per-request round trip to the control database; see §13's
    /// open question on cache lifetime.
    fn resolve(&self, host: &str) -> Resolution;
}

/// How a deployment turns a resolved tenant into a database handle.
///
/// Separate from [`ResolveTenant`] because the two answers come from
/// different places and fail differently: resolution reads a registry row
/// (cheap, cacheable, and a miss means `404`), while this opens or reuses
/// a connection pool (lazy, evictable, and a failure means the tenant is
/// unreachable rather than unknown).
///
/// Implemented by the runtime, never by a module. The registry that backs
/// it is the only thing in the process that knows a DSN
/// (TENANT-ROUTING.md §4): it maps a connect failure to
/// [`TenantDbError::Unreachable`] **before** the URL can reach a log line
/// or a response body. `Display for DbError` already scrubs, so that is
/// not the only defence — but `Debug` derives raw, and a DSN formatted
/// before it ever becomes a `DbError` is scrubbed by nothing. Not
/// producing the string is the first line; the sink is the second.
#[async_trait::async_trait]
pub trait TenantDatabases: Send + Sync {
    /// The handle for `tenant`, opening its pool on first use.
    ///
    /// # Errors
    ///
    /// [`TenantDbError::Unreachable`] when the tenant's database cannot be
    /// reached. The DSN is never part of the error.
    async fn database(
        &self,
        tenant: &Tenant,
    ) -> Result<std::sync::Arc<dyn crate::ports::Database>, TenantDbError>;
}

/// Why a tenant's database could not be handed over. Deliberately carries
/// the tenant id and nothing else — no DSN, no driver message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantDbError {
    /// The pool could not be opened or the server did not answer.
    Unreachable {
        /// Which tenant. Safe to log.
        tenant: String,
    },
}

impl std::fmt::Display for TenantDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { tenant } => {
                write!(f, "tenant `{tenant}`'s database is unreachable")
            }
        }
    }
}

impl std::error::Error for TenantDbError {}

/// A deployment's tenant plane: a host becomes a tenant, and a tenant
/// becomes a database handle.
///
/// One slot on [`Ports`](crate::Ports) rather than two, because the
/// resolution layer needs both halves of the same request and a
/// deployment that supplied only one would be misconfigured in a way no
/// type could catch. The blanket impl means a runtime writes the two
/// traits and gets this for free.
pub trait TenantRouting: ResolveTenant + TenantDatabases {}

impl<T: ResolveTenant + TenantDatabases> TenantRouting for T {}

/// The registry id a deployment without a registry resolves to.
///
/// Not a magic string scattered across three runtimes: one constant, so
/// a log line from a Cloudflare Worker and one from a `cargo test` run
/// say the same word.
pub const IMPLICIT_TENANT: &str = "default";

/// The resolver a deployment with **no control database** uses: every
/// host is the one venture, always `active`.
///
/// This is not the Cloudflare path, it is the *no registry* path — which
/// is also the browser runtime, and native in every development run and
/// every test (TENANT-ROUTING.md §6). Scoping it to Cloudflare would mean
/// `cargo test` cannot resolve a tenant and every module suite 500s.
///
/// A module is therefore written once, against the stricter shape, and
/// the path most ventures actually run in production is not the one
/// without the isolation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImplicitTenant;

impl ResolveTenant for ImplicitTenant {
    fn resolve(&self, _host: &str) -> Resolution {
        Resolution::Found {
            id: IMPLICIT_TENANT.to_owned(),
            status: TenantStatus::Active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Resolution, TenantStatus};

    fn found(status: TenantStatus) -> Resolution {
        Resolution::Found {
            id: "acme".to_owned(),
            status,
        }
    }

    #[test]
    fn the_implicit_tenant_answers_for_every_host() {
        use super::{IMPLICIT_TENANT, ImplicitTenant, ResolveTenant};
        // A deployment with no registry has one tenant, and which host
        // asked is not a question it can answer differently - including
        // for a host it has never seen, which is what a test client and a
        // loopback probe both look like.
        for host in ["acme.example", "localhost:8787", ""] {
            let tenant = ImplicitTenant
                .resolve(host)
                .admit()
                .expect("the implicit tenant always serves");
            assert_eq!(tenant.id().as_str(), IMPLICIT_TENANT);
            assert_eq!(tenant.status(), TenantStatus::Active);
        }
    }

    #[test]
    fn only_an_active_tenant_is_admitted() {
        let tenant = found(TenantStatus::Active)
            .admit()
            .expect("an active tenant serves");
        assert_eq!(tenant.id().as_str(), "acme");
        assert_eq!(tenant.status(), TenantStatus::Active);
    }

    #[test]
    fn provisioning_is_refused_like_degraded_and_not_like_unknown() {
        // Registered but not yet reconciled: the schema is not known to
        // match the code, which is the condition the refusal exists for.
        // The caller's situation is identical to degraded - come back
        // later - so it is one slug, and the operator learns which from
        // the registry rather than from the response.
        for status in [TenantStatus::Provisioning, TenantStatus::Degraded] {
            let problem = found(status).admit().expect_err("must not serve");
            assert_eq!(problem.slug, "tenant-degraded", "for {status}");
            assert_eq!(problem.status.as_u16(), 503);
        }
    }

    #[test]
    fn an_unknown_host_is_a_404_not_a_503() {
        // Distinguishable on purpose: 503 says "this tenant exists and is
        // unwell", 404 says "no such tenant". Collapsing them would tell
        // an operator the wrong thing during an incident.
        let problem = Resolution::Unknown.admit().expect_err("must not serve");
        assert_eq!(problem.slug, "unknown-tenant");
        assert_eq!(problem.status.as_u16(), 404);
    }

    #[test]
    fn a_status_this_binary_does_not_know_is_refused_not_guessed() {
        // `parse` is fail-closed, so a future version writing a status
        // this binary has never heard of reads as degraded and is
        // refused. The alternative - defaulting to active - would serve a
        // tenant on the strength of not understanding it.
        let unknown = TenantStatus::parse("quiesced");
        assert_eq!(unknown, TenantStatus::Degraded);
        assert!(found(unknown).admit().is_err());
    }

    #[test]
    fn serializes_as_the_registry_text_not_the_variant_name() {
        for status in [
            TenantStatus::Active,
            TenantStatus::Provisioning,
            TenantStatus::Degraded,
        ] {
            let json = serde_json::to_string(&status).expect("a unit variant serializes");
            assert_eq!(
                json,
                format!("\"{}\"", status.as_str()),
                "the wire form is the registry's word, so a log field and a row agree"
            );
        }
    }

    #[test]
    fn round_trips_through_the_registry_text() {
        for status in [
            TenantStatus::Active,
            TenantStatus::Provisioning,
            TenantStatus::Degraded,
        ] {
            assert_eq!(TenantStatus::parse(status.as_str()), status);
        }
    }

    #[test]
    fn an_unknown_status_reads_as_degraded() {
        assert_eq!(TenantStatus::parse("busy"), TenantStatus::Degraded);
        assert_eq!(TenantStatus::parse(""), TenantStatus::Degraded);
    }
}
