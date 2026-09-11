//! The tenant lifecycle statuses the control database's registry carries
//! (RECONCILIATION.md §6, ADR 0008). Shared so the reconciler, the CLI
//! and any control-plane consumer say the same three words.

/// A tenant database's reconciliation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::TenantStatus;

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
