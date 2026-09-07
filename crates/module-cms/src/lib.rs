//! `factory0-module-cms`: a small content store with an editor (Cratefield
//! control-plane issue #10).
//!
//! ```no_run
//! use factory0_module_cms::Cms;
//!
//! let module = Cms::new().collections(["pages", "posts"]);
//! ```
//!
//! **A content store, not a page builder.** A content item is a titled body
//! plus a JSON `data` object, addressed by `(collection, slug)`. The editable
//! draft lives in `cms_item`; every publish appends an immutable snapshot to
//! `cms_revision`, so an item is versioned and the history of what was public
//! is recoverable. The look comes from the venture's `UI_SPEC` (the
//! prompt-to-UiSpec work), not from here.
//!
//! **The venture keeps its content.** Everything is in the venture's own
//! database, edited through the harness admin session, so a customer's content
//! never leaves their venture and the module inherits the `/ui` surface, the
//! admin gate, one-database-per-tenant and the audit trail for free. There is
//! no external credential to connect: selecting the CMS provisions its tables
//! and admin UI with the venture.
//!
//! **Public routes are reads.** `GET /v1/cms/{collection}` and
//! `GET /v1/cms/{collection}/{slug}` serve *published* content; every write is
//! an admin action behind the `ADMIN_TOKEN` bearer. So the module has no
//! public write endpoint and needs no captcha.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
mod store;

use factory0_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, SqlMigration,
};
use std::sync::Arc;

/// Which collections a venture allows. A content item names a collection, and
/// a collection outside this set is refused, so a caller cannot invent one.
#[derive(Debug, Clone)]
pub(crate) enum Collections {
    /// Exactly these collection slugs.
    List(Vec<String>),
    /// Any collection slug (a venture that does not want an allowlist).
    Any,
}

/// The module's build-time configuration.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub collections: Collections,
}

/// The one migration: the `cms_item` and `cms_revision` tables in the portable
/// SQL subset.
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

/// A small content store with an editor.
pub struct Cms {
    settings: Settings,
}

impl Default for Cms {
    fn default() -> Self {
        Self::new()
    }
}

impl Cms {
    /// A CMS that, until [`Cms::collections`] or [`Cms::any_collection`] says
    /// otherwise, allows no collection — so a misconfigured venture refuses
    /// content rather than accepting anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: Settings {
                collections: Collections::List(Vec::new()),
            },
        }
    }

    /// Exactly these collection slugs may hold content.
    #[must_use]
    pub fn collections(mut self, collections: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.settings.collections =
            Collections::List(collections.into_iter().map(Into::into).collect());
        self
    }

    /// Accept any collection slug.
    #[must_use]
    pub fn any_collection(mut self) -> Self {
        self.settings.collections = Collections::Any;
        self
    }
}

/// A kebab-case slug: lowercase letters, digits and single hyphens.
fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
}

impl Module for Cms {
    fn name(&self) -> &'static str {
        "cms"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["cms_item", "cms_revision"]
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("cms", cfg);
        let mut errors = ConfigError::default();
        if let Some(list) = cfg.get(&module.key("COLLECTIONS"))
            && list != "*"
            && list.split(',').map(str::trim).all(|slug| !is_slug(slug))
        {
            errors.push(format!(
                "cms: {} must be a comma-separated list of kebab-case slugs or `*`",
                module.key("COLLECTIONS")
            ));
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx), self.settings.clone())
    }

    fn surface(&self) -> factory0_core::Surface {
        handlers::surface(&self.settings)
    }
}
