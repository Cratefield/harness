//! The venture's admin route (issue #652): the orgs module's staff guard as
//! the venture uses it — a staff member gets 200, a signed-in non-staff caller
//! is refused with 403, and a machine holding `ADMIN_TOKEN` gets 200. Runs
//! against SQLite always, and Postgres when `FZ_TEST_POSTGRES_URL` is set.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{HeaderMap, Method, StatusCode};
use cratefield::orgs::Orgs;
use cratefield::{Auth, AuthError, Caller, Config, MapConfig, Ports, Statement, Subject};
use cratefield_testing::{TestHarness, request_as};
use venture::admin::{AdminModule, STAFF_ORG};

/// The admin bearer the deployment is configured with, for the machine path.
const ADMIN: &str = "test-admin-token-0123456789abcdef";
const SEEDED_AT: &str = "2026-01-02T00:00:00Z";

/// A verifier driven by bearer token: `Authorization: Bearer <sub>` proves
/// `<sub>`; no header at all is an anonymous caller.
#[derive(Clone)]
struct TestAuth;

#[async_trait]
impl Auth for TestAuth {
    async fn identify(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
            return Ok(Caller::Anonymous);
        };
        let sub = value
            .to_str()
            .map_err(|_| AuthError::NotVerified)?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::NotVerified)?;
        Ok(Caller::Subject(Subject::new(sub)))
    }
}

/// The venture's composition once per available dialect: the orgs module with
/// the roles and staff organization `src/lib.rs` names, the venture's own admin
/// module, the test verifier, and a config carrying `ADMIN_TOKEN`.
fn harnesses() -> Vec<TestHarness> {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
    TestHarness::all_dialects_with_ports(
        || {
            vec![
                Box::new(
                    Orgs::builder()
                        .roles(["owner", "manager", "staff"])
                        .managers(["manager"])
                        .staff_org(STAFF_ORG)
                        .staff_roles(["staff"])
                        .build(),
                ),
                Box::new(AdminModule),
            ]
        },
        move |ports: &mut Ports| {
            ports.auth = Some(Arc::new(TestAuth));
            ports.config = Arc::clone(&config);
        },
    )
}

/// Writes the staff organization and `sub`'s staff membership straight into
/// storage: the id is named in the builder before any row exists, so a test
/// that needs the two to agree seeds the row itself.
async fn seed_staff(kit: &TestHarness, sub: &str) {
    kit.db
        .batch_atomic(&[
            Statement::with_values(
                "INSERT INTO orgs (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
                vec![
                    STAFF_ORG.into(),
                    "Staff".into(),
                    sub.into(),
                    SEEDED_AT.into(),
                ],
            ),
            Statement::with_values(
                "INSERT INTO org_members (org_id, user_sub, role, invited_by, created_at) \
                 VALUES (?, ?, ?, NULL, ?)",
                vec![
                    STAFF_ORG.into(),
                    sub.into(),
                    "staff".into(),
                    SEEDED_AT.into(),
                ],
            ),
        ])
        .await
        .expect("seeds the staff organization");
}

#[pollster::test]
async fn the_staff_guard_opens_for_a_staff_member_and_for_the_machine_token() {
    for kit in harnesses() {
        seed_staff(&kit, "bob").await;

        let staff = request_as(&kit.router, Method::GET, "/v1/admin/ping", "bob", None).await;
        assert_eq!(staff.status, StatusCode::OK, "{:?}", staff.json());

        let stranger = request_as(&kit.router, Method::GET, "/v1/admin/ping", "carol", None).await;
        assert_eq!(
            stranger.status,
            StatusCode::FORBIDDEN,
            "a signed-in non-staff caller is refused: {:?}",
            stranger.json()
        );

        let machine = request_as(&kit.router, Method::GET, "/v1/admin/ping", ADMIN, None).await;
        assert_eq!(machine.status, StatusCode::OK, "{:?}", machine.json());
    }
}
