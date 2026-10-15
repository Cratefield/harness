//! Service accounts, grants and the audit log against a real database, every
//! available dialect (issue #878).
//!
//! The pure decision rule is unit-tested beside it (`src/grants.rs`); this
//! suite proves the stored half: that every read and write stays inside its
//! organization, that a key verifies only while everything about it is live,
//! that a removed owner's accounts fail closed, and that the log pages
//! newest first.

use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use cratefield_core::{Database, Module};
use cratefield_module_orgs::Orgs;
use cratefield_module_orgs::audit::{self, AuditEntry};
use cratefield_module_orgs::grants::{
    self, Effect, NewGrant, Permission, Resource, Selector, decide, split_path,
};
use cratefield_module_orgs::service_accounts::{
    self as accounts, NewKey, NewServiceAccount, ServiceAccountError,
};
use cratefield_testing::TestHarness;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("in range")
}

/// One database per available dialect. The harness rides along so it lives
/// as long as the loop body that uses its database.
fn dbs() -> Vec<(String, Arc<dyn Database>, TestHarness)> {
    TestHarness::all_dialects(|| vec![Box::new(Orgs::new()) as Box<dyn Module>])
        .into_iter()
        .map(|kit| (kit.dialect.to_owned(), Arc::clone(&kit.db), kit))
        .collect()
}

fn account<'a>(id: &'a str, owner: &'a str) -> NewServiceAccount<'a> {
    NewServiceAccount {
        id,
        name: "CI bot",
        description: "Pushes coding-agent sessions",
        owner_sub: owner,
        created_by: owner,
    }
}

fn key(name: &str) -> NewKey<'_> {
    NewKey {
        brand: "lba",
        name,
        scopes: None,
        expires_at: None,
    }
}

#[pollster::test]
async fn a_key_verifies_once_minted_and_never_after_it_is_revoked() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        accounts::create(db, "org1", &account("agt_1", "alice"), now())
            .await
            .expect("creates");
        let minted = accounts::mint_key(db, "org1", "agt_1", &key("laptop"), now())
            .await
            .expect("mints");
        assert!(minted.key.starts_with(&minted.info.prefix), "{dialect}");

        let principal = accounts::verify_key(db, &minted.key, now())
            .await
            .expect("reads")
            .expect("a live key verifies");
        assert_eq!(principal.account.id, "agt_1", "{dialect}");
        assert_eq!(principal.account.org_id, "org1", "{dialect}");
        assert_eq!(principal.scopes, None, "{dialect}");

        let listed = accounts::keys(db, "org1", "agt_1").await.expect("lists");
        assert_eq!(listed.len(), 1, "{dialect}");
        assert!(listed[0].last_used_at.is_some(), "{dialect}: stamped");

        // A wrong secret under the right prefix is refused.
        let mut forged = minted.key.clone();
        let last = forged.pop().expect("non-empty");
        forged.push(if last == '0' { '1' } else { '0' });
        assert!(
            accounts::verify_key(db, &forged, now())
                .await
                .expect("reads")
                .is_none(),
            "{dialect}"
        );

        assert!(
            accounts::revoke_key(db, "org1", "agt_1", &minted.info.prefix, now())
                .await
                .expect("revokes"),
            "{dialect}"
        );
        assert!(
            accounts::verify_key(db, &minted.key, now())
                .await
                .expect("reads")
                .is_none(),
            "{dialect}: revoked"
        );
    }
}

#[pollster::test]
async fn disabling_an_account_refuses_its_keys_and_no_new_key_is_minted() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        accounts::create(db, "org1", &account("agt_1", "alice"), now())
            .await
            .expect("creates");
        let minted = accounts::mint_key(db, "org1", "agt_1", &key("k"), now())
            .await
            .expect("mints");
        accounts::set_disabled(db, "org1", "agt_1", true, now())
            .await
            .expect("disables");
        assert!(
            accounts::verify_key(db, &minted.key, now())
                .await
                .expect("reads")
                .is_none(),
            "{dialect}"
        );
        assert!(
            matches!(
                accounts::mint_key(db, "org1", "agt_1", &key("k2"), now()).await,
                Err(ServiceAccountError::NotFound)
            ),
            "{dialect}"
        );
        accounts::set_disabled(db, "org1", "agt_1", false, now())
            .await
            .expect("enables");
        assert!(
            accounts::verify_key(db, &minted.key, now())
                .await
                .expect("reads")
                .is_some(),
            "{dialect}: re-enabled"
        );
    }
}

#[pollster::test]
async fn an_expired_key_is_refused_and_rotation_keeps_its_settings() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        accounts::create(db, "org1", &account("agt_1", "alice"), now())
            .await
            .expect("creates");
        let minted = accounts::mint_key(
            db,
            "org1",
            "agt_1",
            &NewKey {
                brand: "lba",
                name: "short",
                scopes: Some("shared  personal:alice/coding-agents"),
                expires_at: Some(now() + Duration::hours(1)),
            },
            now(),
        )
        .await
        .expect("mints");
        let principal = accounts::verify_key(db, &minted.key, now())
            .await
            .expect("reads")
            .expect("verifies");
        assert_eq!(
            principal.scopes,
            Some(vec![
                "shared".to_owned(),
                "personal:alice/coding-agents".to_owned()
            ]),
            "{dialect}"
        );

        let rotated = accounts::rotate_key(db, "org1", "agt_1", &minted.info.prefix, "lba", now())
            .await
            .expect("rotates");
        assert_ne!(rotated.key, minted.key, "{dialect}");
        assert_eq!(rotated.info.scopes, minted.info.scopes, "{dialect}");
        assert_eq!(rotated.info.expires_at, minted.info.expires_at, "{dialect}");
        assert!(
            accounts::verify_key(db, &minted.key, now())
                .await
                .expect("reads")
                .is_none(),
            "{dialect}: the old key is revoked"
        );

        let later = now() + Duration::hours(2);
        assert!(
            accounts::verify_key(db, &rotated.key, later)
                .await
                .expect("reads")
                .is_none(),
            "{dialect}: past its expiry"
        );
        assert!(
            accounts::rotate_key(db, "org1", "agt_1", &rotated.info.prefix, "lba", later)
                .await
                .is_err(),
            "{dialect}: an expired key cannot be rotated into a live one"
        );
    }
}

#[pollster::test]
async fn accounts_and_keys_stay_inside_their_organization() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        accounts::create(db, "org1", &account("agt_1", "alice"), now())
            .await
            .expect("creates");
        let minted = accounts::mint_key(db, "org1", "agt_1", &key("k"), now())
            .await
            .expect("mints");
        assert!(
            accounts::get(db, "org2", "agt_1")
                .await
                .expect("reads")
                .is_none(),
            "{dialect}"
        );
        assert!(
            accounts::list(db, "org2", None)
                .await
                .expect("lists")
                .is_empty(),
            "{dialect}"
        );
        assert!(
            accounts::keys(db, "org2", "agt_1")
                .await
                .expect("lists")
                .is_empty(),
            "{dialect}"
        );
        assert!(
            !accounts::revoke_key(db, "org2", "agt_1", &minted.info.prefix, now())
                .await
                .expect("writes"),
            "{dialect}: another org cannot revoke it"
        );
        assert!(
            matches!(
                accounts::set_disabled(db, "org2", "agt_1", true, now()).await,
                Err(ServiceAccountError::NotFound)
            ),
            "{dialect}"
        );
        assert!(
            matches!(
                accounts::mint_key(db, "org2", "agt_1", &key("k"), now()).await,
                Err(ServiceAccountError::NotFound)
            ),
            "{dialect}: another org cannot mint for it"
        );
        assert!(
            accounts::verify_key(db, &minted.key, now())
                .await
                .expect("reads")
                .is_some(),
            "{dialect}: untouched"
        );
    }
}

#[pollster::test]
async fn removing_an_owner_disables_their_accounts_and_revokes_their_keys() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        accounts::create(db, "org1", &account("agt_1", "alice"), now())
            .await
            .expect("creates");
        accounts::create(db, "org1", &account("agt_2", "bob"), now())
            .await
            .expect("creates");
        let alices = accounts::mint_key(db, "org1", "agt_1", &key("k"), now())
            .await
            .expect("mints");
        let bobs = accounts::mint_key(db, "org1", "agt_2", &key("k"), now())
            .await
            .expect("mints");
        let disabled = accounts::disable_owned_by(db, "org1", "alice", now())
            .await
            .expect("disables");
        assert_eq!(disabled, 1, "{dialect}");
        assert!(
            accounts::verify_key(db, &alices.key, now())
                .await
                .expect("reads")
                .is_none(),
            "{dialect}"
        );
        let keys = accounts::keys(db, "org1", "agt_1").await.expect("lists");
        assert!(
            keys[0].revoked_at.is_some(),
            "{dialect}: revoked, not only disabled"
        );
        assert!(
            accounts::verify_key(db, &bobs.key, now())
                .await
                .expect("reads")
                .is_some(),
            "{dialect}: somebody else's account is untouched"
        );

        assert!(
            accounts::delete(db, "org1", "agt_2")
                .await
                .expect("deletes")
        );
        assert!(
            accounts::verify_key(db, &bobs.key, now())
                .await
                .expect("reads")
                .is_none(),
            "{dialect}: a deleted account's key is gone"
        );
    }
}

#[pollster::test]
async fn invalid_accounts_and_keys_are_refused() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        let blank = NewServiceAccount {
            name: "  ",
            ..account("agt_1", "alice")
        };
        assert!(
            matches!(
                accounts::create(db, "org1", &blank, now()).await,
                Err(ServiceAccountError::Invalid(_))
            ),
            "{dialect}"
        );
        accounts::create(db, "org1", &account("agt_1", "alice"), now())
            .await
            .expect("creates");
        for bad in [
            NewKey {
                brand: "LBA",
                ..key("k")
            },
            NewKey {
                scopes: Some("  "),
                ..key("k")
            },
        ] {
            assert!(
                matches!(
                    accounts::mint_key(db, "org1", "agt_1", &bad, now()).await,
                    Err(ServiceAccountError::Invalid(_))
                ),
                "{dialect}: {bad:?}"
            );
        }
        for junk in ["", "lba_", "lba_00_11", "Bearer lba_x"] {
            assert!(
                accounts::verify_key(db, junk, now())
                    .await
                    .expect("reads")
                    .is_none(),
                "{dialect}: {junk:?}"
            );
        }
    }
}

fn selector(kind: &str, space: &str, path: &str) -> Selector {
    Selector::new(kind, space, split_path(path)).expect("valid")
}

#[pollster::test]
async fn stored_grants_round_trip_upsert_and_stay_inside_their_organization() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        let read = NewGrant {
            principal: "member:bob".to_owned(),
            selector: selector("pages", "personal:alice", "coding-agents/claude"),
            permission: Permission::Read,
            effect: Effect::Allow,
            expires_at: None,
            created_by: "alice".to_owned(),
        };
        let first = grants::put_grant(db, "org1", "g1", &read, now())
            .await
            .expect("stores");
        // The same principal, selector and effect again is the same row, now
        // at the new permission.
        let write = NewGrant {
            permission: Permission::Write,
            ..read.clone()
        };
        let second = grants::put_grant(db, "org1", "g2", &write, now())
            .await
            .expect("stores");
        assert_eq!(first, second, "{dialect}");
        let deny = NewGrant {
            effect: Effect::Deny,
            selector: selector("pages", "personal:alice", "coding-agents/claude/secret"),
            ..read.clone()
        };
        grants::put_grant(db, "org1", "g3", &deny, now())
            .await
            .expect("stores");

        let held = grants::grants_for(db, "org1", &["member:bob", "role:member"])
            .await
            .expect("reads");
        assert_eq!(held.len(), 2, "{dialect}");
        let ask = |path: &str, permission| {
            decide(
                &held,
                &["member:bob"],
                &Resource::new("pages", "personal:alice", split_path(path)).expect("valid"),
                permission,
                now(),
            )
            .is_allowed()
        };
        assert!(
            ask("coding-agents/claude/x", Permission::Write),
            "{dialect}"
        );
        assert!(
            !ask("coding-agents/claude/secret/x", Permission::Read),
            "{dialect}"
        );
        assert!(!ask("coding-agents/codex/x", Permission::Read), "{dialect}");

        assert!(
            grants::grants_for(db, "org2", &["member:bob"])
                .await
                .expect("reads")
                .is_empty(),
            "{dialect}: another org sees none"
        );
        assert!(
            !grants::delete_grant(db, "org2", &first)
                .await
                .expect("writes"),
            "{dialect}: nor deletes one"
        );
        assert_eq!(
            grants::grants_on_space(db, "org1", "personal:alice")
                .await
                .expect("reads")
                .len(),
            2,
            "{dialect}"
        );
        assert!(
            grants::grant(db, "org1", &first)
                .await
                .expect("reads")
                .is_some()
        );
        assert!(
            grants::delete_grant(db, "org1", &first)
                .await
                .expect("deletes")
        );
        assert_eq!(
            grants::delete_grants_for(db, "org1", "member:bob")
                .await
                .expect("deletes"),
            1,
            "{dialect}"
        );
        assert!(
            grants::grants_in_org(db, "org1")
                .await
                .expect("reads")
                .is_empty(),
            "{dialect}"
        );
    }
}

#[pollster::test]
async fn a_corrupt_deny_fails_closed_and_a_corrupt_allow_grants_nothing() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        for (id, effect, permission) in [("a", "allow", "everything"), ("d", "deny", "bogus")] {
            db.execute(&cratefield_core::Statement::with_values(
                "INSERT INTO org_grants (id, org_id, principal, kind, space, path, permission, \
                 effect, created_by, created_at) VALUES (?, 'org1', 'p', 'pages', 's', '', ?, ?, \
                 'x', '2026-01-01T00:00:00Z')",
                vec![id.into(), permission.into(), effect.into()],
            ))
            .await
            .expect("seeds");
        }
        let held = grants::grants_for(db, "org1", &["p"]).await.expect("reads");
        assert_eq!(held.len(), 1, "{dialect}: only the deny survives");
        assert_eq!(held[0].effect, Effect::Deny, "{dialect}");
        assert_eq!(
            held[0].selector.kind(),
            "*",
            "{dialect}: widened to the space"
        );
    }
}

#[pollster::test]
async fn the_audit_log_pages_newest_first_and_strips_control_characters() {
    for (dialect, db, _kit) in dbs() {
        let db = &*db;
        for n in 0..5 {
            audit::record(
                db,
                &AuditEntry {
                    id: format!("01J0000000000000000000000{n}"),
                    org_id: "org1".to_owned(),
                    actor_kind: "service_account".to_owned(),
                    actor_id: "agt_1".to_owned(),
                    on_behalf_of: Some("alice".to_owned()),
                    credential: "lba_0011223344556677".to_owned(),
                    action: "page.write".to_owned(),
                    resource: format!("pages:personal:alice/x{n}"),
                    detail: "a\u{1b}[31mb".to_owned(),
                    at: String::new(),
                },
                now(),
            )
            .await
            .expect("records");
        }
        let page = audit::list(db, "org1", None, 2).await.expect("lists");
        assert_eq!(page.len(), 2, "{dialect}");
        assert!(page[0].id > page[1].id, "{dialect}: newest first");
        assert_eq!(page[0].detail, "a[31mb", "{dialect}: no escape");
        assert_eq!(page[0].on_behalf_of.as_deref(), Some("alice"));
        let next = audit::list(db, "org1", Some(&page[1].id), 10)
            .await
            .expect("lists");
        assert_eq!(next.len(), 3, "{dialect}");
        assert!(next.iter().all(|entry| entry.id < page[1].id), "{dialect}");
        assert!(
            audit::list(db, "org2", None, 10)
                .await
                .expect("lists")
                .is_empty(),
            "{dialect}"
        );
    }
}
