//! `cratefield-module-crm`: contacts, organisations and tags (Cratefield
//! issue #572).
//!
//! ```no_run
//! use cratefield_module_crm::Crm;
//!
//! let module = Crm::new();
//! ```
//!
//! **Idempotent by natural key.** The module exists so other modules and a
//! venture's own code can file a person or a company without first asking
//! whether it is already there: [`store::upsert_contact`] keys a contact on
//! its normalized address and [`store::upsert_organisation`] keys an
//! organisation on its domain, so the same address twice is one contact and
//! the second call updates rather than duplicates.
//!
//! **Every write is optimistic.** A row carries a `generation` that every
//! write bumps; a PATCH must carry the generation it read, and a mismatch is
//! a `409` (`crm-stale-generation`) rather than a lost update.
//!
//! **The routes are admin-only.** Contacts, organisations, their CSV exports
//! and the tag operations all sit under `/v1/crm/admin/` behind the harness
//! `ADMIN_TOKEN` bearer, so the module has no public write endpoint and needs
//! no captcha.
//!
//! A contact is personal data and is erased with its taggings; an
//! organisation is a business record and survives. See [`Crm::personal_data`]
//! for the declarations the privacy module reads.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
pub mod store;

use std::sync::Arc;

use cratefield_core::{
    Config, ConfigError, DataKind, Disposition, Migrations, Module, ModuleContext, PersonalDataSet,
    Port, SqlMigration, SubjectVia, Surface,
};

/// The module's name: it is mounted at `/v1/crm`, and its config keys are
/// prefixed `CRM_`.
pub const MODULE_NAME: &str = "crm";

/// The module's one migration: its four tables in the portable SQL subset
/// (ADR 0004). One file serves SQLite, D1 and Postgres, so there is no
/// `migrations/postgres` override.
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The module's four tables, in the order `tables()` lists them.
const TABLES: &[&str] = &[
    "crm_contacts",
    "crm_organisations",
    "crm_tags",
    "crm_taggings",
];

/// A CRM: contacts, organisations and the tags that label them.
#[derive(Debug, Default, Clone, Copy)]
pub struct Crm;

impl Crm {
    /// A CRM. It takes no settings: every route is admin-gated, and there is
    /// nothing to configure, so [`Module::validate_config`] accepts anything.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Module for Crm {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::IdGen, Port::Clock]
    }

    /// `Auth` is declared because a venture may want to file contacts for the
    /// signed-in caller, and declaring it here keeps that port visible to the
    /// module rather than silently stripped. No route reads it yet; the
    /// conformance kit allows a declared-but-unused optional port (issue
    /// #450), so leaving it off the list until a route needs it would also be
    /// correct — this is the deliberate side of that choice.
    fn optional(&self) -> &'static [Port] {
        &[Port::Auth]
    }

    fn tables(&self) -> &'static [&'static str] {
        TABLES
    }

    /// What each table holds about a person.
    ///
    /// The order is load-bearing. `cratefield-module-privacy` erases in
    /// **reverse** catalog order, so the tables are declared parent-first:
    /// `crm_taggings` is last, and its rows — which reach a contact through
    /// `crm_contacts` — are deleted before the contact they name.
    ///
    /// `crm_taggings` declares [`SubjectVia`] rather than a plain subject
    /// because its `subject_id` is polymorphic and there is no foreign key to
    /// filter on. The join cannot express `subject_type = 'contact'`, so it
    /// matches a contact id in `subject_id` whatever the type says — safe
    /// only because those ids are unique ULIDs that no organisation or item
    /// row shares.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet {
                table: "crm_contacts",
                subject: "id",
                kind: DataKind::Contact,
                disposition: Disposition::Erase,
                description: "One person or lead: their email address, name, phone number, \
                              locale, an optional link to the organisation they belong to, the \
                              source they arrived from, and any structured fields the venture \
                              keeps alongside them.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet::none(
                "crm_organisations",
                "The companies this venture deals with, a business record rather than a \
                 person's: name, domain, website and postal address. Review before relying on \
                 this: `email` and `phone` may hold an individual's details rather than a \
                 shared switchboard, and a sole trader's record is a person's data in \
                 practice. Erasure does not reach these rows today.",
            ),
            PersonalDataSet::none(
                "crm_tags",
                "The labels a venture files its records under — a name and a colour. Nothing \
                 in this table names a person.",
            ),
            PersonalDataSet {
                table: "crm_taggings",
                subject: "subject_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "Which labels are filed against which record. The row holds a tag \
                              and the id of whatever it labels — a contact, an organisation, or \
                              an item the venture owns — so it is erased with the contact it \
                              names.",
                redacted: &[],
                subject_via: Some(SubjectVia {
                    table: "crm_contacts",
                    subject: "id",
                    key: "id",
                }),
            },
        ];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        &[
            handlers::EVENT_CONTACT_CREATED,
            handlers::EVENT_CONTACT_UPDATED,
            handlers::EVENT_ORGANISATION_CREATED,
        ]
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        // The array is the apply order; this refuses a gap, a duplicate or an
        // entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        // No keys: every route is admin-gated and every default is a constant.
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx))
    }

    fn surface(&self) -> Surface {
        handlers::surface()
    }
}
