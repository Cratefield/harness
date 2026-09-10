//! The catalogue of every `fz doctor` error code (harness #140): stable
//! kebab-case slugs an agent can branch on forever, the seed of the MCP
//! server's "stable error-code catalogue" (issue #160). Modelled on
//! `cratefield_core::problems`: a struct of `&'static` definitions, a
//! registry function, stable string codes.
//!
//! The contract: a code is never renamed, reworded or removed. A failure
//! *message* may change wording freely; a *code* may not. New codes append.

/// Definition of one doctor error code.
#[derive(Debug, Clone, Copy)]
pub struct DoctorCodeDef {
    /// The stable kebab-case code, exactly as `fz doctor --json` emits it.
    pub code: &'static str,
    /// Short, stable human title.
    pub title: &'static str,
    /// One-line description for consumers; not part of the JSON output.
    pub description: &'static str,
}

/// Every code the doctor emits. Keep the registry below sorted by code.
pub struct Codes {
    /// A module was built against a different `HARNESS_API` than the
    /// core crate it linked against.
    pub harness_api_mismatch: DoctorCodeDef,
    /// The `.harness-lock.json` could not be read or parsed.
    pub lockfile_unreadable: DoctorCodeDef,
    /// A module migration has no locked file yet — run
    /// `fz migrations collect` first.
    pub migration_not_collected: DoctorCodeDef,
    /// A locked migration's file is missing from disk.
    pub locked_migration_missing: DoctorCodeDef,
    /// A locked migration's file no longer matches its pinned sha256.
    pub locked_migration_edited: DoctorCodeDef,
    /// The production captcha rule: captcha-guarded public writes
    /// without an effectively configured Captcha port.
    pub captcha_not_effective: DoctorCodeDef,
    /// The production payments rule: signature-guarded routes without
    /// `STRIPE_WEBHOOK_SECRET`.
    pub payments_webhook_secret_missing: DoctorCodeDef,
    /// A sidecar mount names a module compiled into this venture; the
    /// runtime ignores the mount.
    pub sidecar_shadows_module: DoctorCodeDef,
    /// The sidecar mount table could not be parsed.
    pub sidecar_mount_invalid: DoctorCodeDef,
    /// A migration contains SQL outside the portable subset.
    pub non_portable_sql: DoctorCodeDef,
    /// A migration contains card data (number, verification code or
    /// full expiry).
    pub card_data_in_migration: DoctorCodeDef,
}

pub const CODES: Codes = Codes {
    harness_api_mismatch: DoctorCodeDef {
        code: "harness-api-mismatch",
        title: "Harness API mismatch",
        description: "A module was built against a different HARNESS_API than the core crate this venture linked.",
    },
    lockfile_unreadable: DoctorCodeDef {
        code: "lockfile-unreadable",
        title: "Lockfile unreadable",
        description: "The .harness-lock.json could not be read or parsed.",
    },
    migration_not_collected: DoctorCodeDef {
        code: "migration-not-collected",
        title: "Migration not collected",
        description: "A module migration has no locked file yet; run `fz migrations collect`.",
    },
    locked_migration_missing: DoctorCodeDef {
        code: "locked-migration-missing",
        title: "Locked migration missing",
        description: "A locked migration's file is missing from disk.",
    },
    locked_migration_edited: DoctorCodeDef {
        code: "locked-migration-edited",
        title: "Locked migration edited",
        description: "A locked migration's file no longer matches its pinned sha256; restore it or add a new migration.",
    },
    captcha_not_effective: DoctorCodeDef {
        code: "captcha-not-effective",
        title: "Captcha not effective",
        description: "A production venture has captcha-guarded public writes but the Captcha port is not effectively configured.",
    },
    payments_webhook_secret_missing: DoctorCodeDef {
        code: "payments-webhook-secret-missing",
        title: "Payments webhook secret missing",
        description: "A production venture has signature-guarded routes but STRIPE_WEBHOOK_SECRET is unset.",
    },
    sidecar_shadows_module: DoctorCodeDef {
        code: "sidecar-shadows-module",
        title: "Sidecar shadows a compiled-in module",
        description: "A sidecar mount names a module compiled into this venture; the runtime ignores the mount.",
    },
    sidecar_mount_invalid: DoctorCodeDef {
        code: "sidecar-mount-invalid",
        title: "Sidecar mount invalid",
        description: "The sidecar mount table could not be parsed.",
    },
    non_portable_sql: DoctorCodeDef {
        code: "non-portable-sql",
        title: "Non-portable SQL",
        description: "A migration contains SQL outside the portable subset (dialect-specific tokens).",
    },
    card_data_in_migration: DoctorCodeDef {
        code: "card-data-in-migration",
        title: "Card data in migration",
        description: "A migration contains card data: a card number, verification code or full expiry.",
    },
};

/// Every doctor code definition, for tests and docs. Sorted by code.
#[must_use]
pub fn registry() -> Vec<&'static DoctorCodeDef> {
    vec![
        &CODES.captcha_not_effective,
        &CODES.card_data_in_migration,
        &CODES.harness_api_mismatch,
        &CODES.locked_migration_edited,
        &CODES.locked_migration_missing,
        &CODES.lockfile_unreadable,
        &CODES.migration_not_collected,
        &CODES.non_portable_sql,
        &CODES.payments_webhook_secret_missing,
        &CODES.sidecar_mount_invalid,
        &CODES.sidecar_shadows_module,
    ]
}

#[cfg(test)]
mod tests {
    use super::{CODES, registry};

    /// A code is lowercase kebab-case: an agent regexes it, so it must
    /// stay machine-shaped forever.
    #[test]
    fn codes_are_kebab_case() {
        for def in registry() {
            assert!(
                !def.code.is_empty()
                    && def
                        .code
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                    && !def.code.starts_with('-')
                    && !def.code.ends_with('-')
                    && !def.code.contains("--"),
                "{:?} must be lowercase kebab-case",
                def.code
            );
            assert!(!def.title.is_empty(), "{:?} needs a title", def.code);
            assert!(
                !def.description.is_empty(),
                "{:?} needs a description",
                def.code
            );
        }
    }

    /// Every catalogue field is registered exactly once — the registry
    /// is the whole catalogue, and a code that drifts from its slug
    /// fails here.
    #[test]
    fn registry_covers_every_field_exactly_once_and_is_sorted() {
        let registered = registry();
        let mut by_slug: Vec<&str> = registered.iter().map(|def| def.code).collect();
        let mut expected = by_slug.clone();
        expected.sort_unstable();
        assert_eq!(by_slug, expected, "registry must stay sorted by code");
        by_slug.dedup();
        assert_eq!(by_slug.len(), registered.len(), "duplicate code registered");

        let fields = [
            CODES.harness_api_mismatch.code,
            CODES.lockfile_unreadable.code,
            CODES.migration_not_collected.code,
            CODES.locked_migration_missing.code,
            CODES.locked_migration_edited.code,
            CODES.captcha_not_effective.code,
            CODES.payments_webhook_secret_missing.code,
            CODES.sidecar_shadows_module.code,
            CODES.sidecar_mount_invalid.code,
            CODES.non_portable_sql.code,
            CODES.card_data_in_migration.code,
        ];
        assert_eq!(fields.len(), registered.len());
        for field in fields {
            assert!(
                registered.iter().any(|def| def.code == field),
                "{field} is in the catalogue but not the registry"
            );
        }
    }
}
