//! The venture's own admin route (issue #652): one endpoint whose guard is the
//! orgs module's `require_staff`, showing where a venture hangs a route off the
//! staff role — or the `ADMIN_TOKEN` machine — the module's admin listing uses.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use cratefield::orgs::require_staff;
use cratefield::{Config, ConfigError, Json, Migrations, Module, ModuleContext, Port, Problem};
use serde_json::json;
use std::sync::Arc;

/// The staff organization's id and the role in it that may use the admin
/// routes. `lib.rs` hands these same constants to the `Orgs` builder, so the
/// guard and the module cannot be told about different roles.
pub const STAFF_ORG: &str = "org-staff";
pub const STAFF_ROLE: &str = "staff";

/// The venture's admin routes, mounted at `/v1/admin`.
pub struct AdminModule;

impl Module for AdminModule {
    fn name(&self) -> &'static str {
        "admin"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The guard reads a membership, so it needs the database, and verifies the
    /// caller, so it needs the verifier; without both declared the harness
    /// hands the route neither.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Auth]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        axum::Router::new().route("/ping", get(ping).with_state(Arc::new(ctx)))
    }
}

/// `GET /v1/admin/ping`: 200 for a machine holding `ADMIN_TOKEN` or a staff
/// member, 403 for a signed-in non-staff caller, 401 for a caller with no
/// credential.
async fn ping(
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Problem> {
    let staff = require_staff(&ctx, &headers, STAFF_ORG, &[STAFF_ROLE]).await?;
    Ok(Json(json!({ "ok": true, "staff": staff.subject })))
}
