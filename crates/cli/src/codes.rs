//! The catalogue of every `fz` error code: stable kebab-case slugs an
//! agent can branch on forever, the seed of the MCP server's "stable
//! error-code catalogue" (issue #160). Modelled on
//! `cratefield_core::problems`: a struct of `&'static` definitions, a
//! registry function, stable string codes. Seeded by `fz doctor` (#220);
//! the agent-safe workflow commands (`fz plan` / `deploy` / `add` /
//! `init` / `verify`, harness #140) appended theirs.
//!
//! The contract: a code is never renamed, reworded or removed. A failure
//! *message* may change wording freely; a *code* may not. New codes append.

/// Definition of one `fz` error code.
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
    /// A module found a problem in its own embedded data — a catalog
    /// missing a translation it declared, and anything else a module
    /// reports from `Module::self_check`.
    pub module_self_check: DoctorCodeDef,
    /// A migration contains SQL outside the portable subset.
    pub non_portable_sql: DoctorCodeDef,
    /// A migration contains card data (number, verification code or
    /// full expiry).
    pub card_data_in_migration: DoctorCodeDef,
    /// A push transport is half-wired, or its credentials were refused:
    /// either way it routes nothing and every send to it reports
    /// `NotConfigured`.
    pub push_transport_misconfigured: DoctorCodeDef,
    /// The production push rule: modules that `requires()` the Push port
    /// on a venture whose environment routes no transport at all.
    pub push_required_but_unrouted: DoctorCodeDef,
    /// The workflow commands (#140): `fz add` / `fz init` name a slug
    /// the catalog does not carry.
    pub module_unknown: DoctorCodeDef,
    /// `fz verify`: no deployment is recorded for this manifest.
    pub not_deployed: DoctorCodeDef,
    /// A production deploy without the explicit
    /// `--i-am-deploying-to-production` consent flag.
    pub production_deploy_unauthorized: DoctorCodeDef,
    /// `fz deploy --plan <digest>`: the digest does not match a plan
    /// recomputed from the current inputs.
    pub stale_plan: DoctorCodeDef,
    /// `fz verify`: the recorded deployment's module set no longer
    /// matches the manifest's resolved composition.
    pub composition_drift: DoctorCodeDef,
    /// `fz verify`: the recorded deployment's config no longer matches
    /// the manifest's.
    pub config_drift: DoctorCodeDef,
    /// `fz deploy` was run without `--plan <digest>`: approval is the
    /// point, so there is no default.
    pub deploy_plan_required: DoctorCodeDef,
    /// The `.harness-deploy.json` record could not be read or parsed.
    pub deploy_record_unreadable: DoctorCodeDef,
    /// The plan removes modules from the served composition (their data
    /// leaves the venture) without the explicit destructive-change
    /// consent flag.
    pub destructive_change_unauthorized: DoctorCodeDef,
    /// `fz verify`: the resolved deployment environment changed since
    /// the recorded deployment.
    pub env_drift: DoctorCodeDef,
    /// `fz verify`: the recorded digest no longer matches a plan
    /// recomputed now, and no narrower drift (composition, config, env)
    /// explains it — the change is in the venture's identity or seed.
    pub manifest_drift: DoctorCodeDef,
    /// `fz init` was pointed at a manifest that already exists, without
    /// `--force`.
    pub manifest_exists: DoctorCodeDef,
    /// A manifest parsed but does not resolve: empty name/host, a
    /// duplicate module, or a selection the catalog refuses.
    pub manifest_invalid: DoctorCodeDef,
    /// The venture manifest could not be read or parsed.
    pub manifest_unreadable: DoctorCodeDef,
    /// A manifest could not be written back to disk.
    pub manifest_write_failed: DoctorCodeDef,
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
    module_self_check: DoctorCodeDef {
        code: "module-self-check",
        title: "Module self-check failed",
        description: "A module reported a problem in its own embedded data, such as a \
                      localisation catalog missing a message it declared.",
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
    push_transport_misconfigured: DoctorCodeDef {
        code: "push-transport-misconfigured",
        title: "Push transport misconfigured",
        description: "A push transport has some of its variables set and some unset, or its credentials were refused; it is left unrouted.",
    },
    push_required_but_unrouted: DoctorCodeDef {
        code: "push-required-but-unrouted",
        title: "Push required but unrouted",
        description: "A production venture has modules that require the Push port but its environment routes no push transport.",
    },
    module_unknown: DoctorCodeDef {
        code: "module-unknown",
        title: "Module unknown",
        description: "`fz add` / `fz init` name a slug the catalog does not carry.",
    },
    not_deployed: DoctorCodeDef {
        code: "not-deployed",
        title: "Not deployed",
        description: "`fz verify` finds no deployment recorded for this manifest.",
    },
    production_deploy_unauthorized: DoctorCodeDef {
        code: "production-deploy-unauthorized",
        title: "Production deploy unauthorized",
        description: "A production deploy without the explicit --i-am-deploying-to-production consent flag.",
    },
    stale_plan: DoctorCodeDef {
        code: "stale-plan",
        title: "Stale plan",
        description: "`fz deploy --plan <digest>`: the digest does not match a plan recomputed from the current inputs.",
    },
    composition_drift: DoctorCodeDef {
        code: "composition-drift",
        title: "Composition drift",
        description: "The recorded deployment's module set no longer matches the manifest's resolved composition.",
    },
    config_drift: DoctorCodeDef {
        code: "config-drift",
        title: "Config drift",
        description: "The recorded deployment's config no longer matches the manifest's.",
    },
    deploy_plan_required: DoctorCodeDef {
        code: "deploy-plan-required",
        title: "Deploy plan required",
        description: "`fz deploy` refuses to run without --plan <digest>; approval is the point.",
    },
    deploy_record_unreadable: DoctorCodeDef {
        code: "deploy-record-unreadable",
        title: "Deploy record unreadable",
        description: "The .harness-deploy.json record could not be read or parsed.",
    },
    destructive_change_unauthorized: DoctorCodeDef {
        code: "destructive-change-unauthorized",
        title: "Destructive change unauthorized",
        description: "The plan removes modules (their data leaves the venture) without the explicit consent flag.",
    },
    env_drift: DoctorCodeDef {
        code: "env-drift",
        title: "Environment drift",
        description: "The resolved deployment environment changed since the recorded deployment.",
    },
    manifest_drift: DoctorCodeDef {
        code: "manifest-drift",
        title: "Manifest drift",
        description: "The recorded digest no longer matches a recomputed plan and no narrower drift explains it.",
    },
    manifest_exists: DoctorCodeDef {
        code: "manifest-exists",
        title: "Manifest exists",
        description: "`fz init` was pointed at an existing manifest without --force.",
    },
    manifest_invalid: DoctorCodeDef {
        code: "manifest-invalid",
        title: "Manifest invalid",
        description: "A manifest parsed but does not resolve: empty name/host, duplicate module, or a refused selection.",
    },
    manifest_unreadable: DoctorCodeDef {
        code: "manifest-unreadable",
        title: "Manifest unreadable",
        description: "The venture manifest could not be read or parsed.",
    },
    manifest_write_failed: DoctorCodeDef {
        code: "manifest-write-failed",
        title: "Manifest write failed",
        description: "A manifest could not be written back to disk.",
    },
};

/// Every `fz` code definition, for tests and docs. Sorted by code.
#[must_use]
pub fn registry() -> Vec<&'static DoctorCodeDef> {
    vec![
        &CODES.captcha_not_effective,
        &CODES.card_data_in_migration,
        &CODES.composition_drift,
        &CODES.config_drift,
        &CODES.deploy_plan_required,
        &CODES.deploy_record_unreadable,
        &CODES.destructive_change_unauthorized,
        &CODES.env_drift,
        &CODES.harness_api_mismatch,
        &CODES.locked_migration_edited,
        &CODES.locked_migration_missing,
        &CODES.lockfile_unreadable,
        &CODES.manifest_drift,
        &CODES.manifest_exists,
        &CODES.manifest_invalid,
        &CODES.manifest_unreadable,
        &CODES.manifest_write_failed,
        &CODES.migration_not_collected,
        &CODES.module_self_check,
        &CODES.module_unknown,
        &CODES.non_portable_sql,
        &CODES.not_deployed,
        &CODES.payments_webhook_secret_missing,
        &CODES.production_deploy_unauthorized,
        &CODES.push_required_but_unrouted,
        &CODES.push_transport_misconfigured,
        &CODES.sidecar_mount_invalid,
        &CODES.sidecar_shadows_module,
        &CODES.stale_plan,
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
            CODES.push_transport_misconfigured.code,
            CODES.push_required_but_unrouted.code,
            CODES.module_self_check.code,
            CODES.module_unknown.code,
            CODES.not_deployed.code,
            CODES.production_deploy_unauthorized.code,
            CODES.stale_plan.code,
            CODES.composition_drift.code,
            CODES.config_drift.code,
            CODES.deploy_plan_required.code,
            CODES.deploy_record_unreadable.code,
            CODES.destructive_change_unauthorized.code,
            CODES.env_drift.code,
            CODES.manifest_drift.code,
            CODES.manifest_exists.code,
            CODES.manifest_invalid.code,
            CODES.manifest_unreadable.code,
            CODES.manifest_write_failed.code,
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
