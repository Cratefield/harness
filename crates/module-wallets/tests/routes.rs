//! The four routes, driven end to end: a signed-in person proves they
//! control a wallet, and the wallet shows up on their own list and nowhere
//! else.
//!
//! Everything here signs in-process from a fixed seed and never touches a
//! chain. The EVM path is EIP-191 `personal_sign` over an EIP-4361 message;
//! the Solana path is a verbatim SIWS signature.

mod support;

use axum::http::{Method, StatusCode};
use cratefield_testing::TestHarness;
use serde_json::{Value, json};

use support::{
    ALICE, DOMAIN, EvmWallet, SolanaWallet, Spec, fixture, kit, links, list, nonce, send_anonymous,
    send_as, test_clock, unlink, verify, verify_body,
};

// ---------------------------------------------------------------------------
// The nonce

#[pollster::test]
async fn a_signed_in_caller_mints_a_nonce_carrying_every_message_field() {
    let (kit, _clock) = fixture();

    let response = send_as(
        &kit,
        ALICE,
        Method::POST,
        "/v1/wallets/nonce",
        Some(&json!({ "chain": "evm" })),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["domain"], json!(DOMAIN));
    assert_eq!(body["uri"], json!("https://wallet.test"));
    assert_eq!(
        body["statement"],
        json!("Link this wallet to your account.")
    );
    assert_eq!(body["version"], json!("1"));
    assert_eq!(body["chain_id"], json!("1"));
    assert_eq!(body["chain"], json!("evm"));
    let nonce = body["nonce"].as_str().expect("nonce");
    assert!(nonce.len() >= 8, "{nonce}");
    assert!(
        nonce.chars().all(|ch| ch.is_ascii_alphanumeric()),
        "the nonce is alphanumeric so it survives a URL unescaped: {nonce}"
    );
    assert!(
        body["issued_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );
    assert!(
        body["expiration_time"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );

    // Two nonces in a row differ: the entropy source is a counter, not a
    // constant.
    let second = send_as(
        &kit,
        ALICE,
        Method::POST,
        "/v1/wallets/nonce",
        Some(&json!({ "chain": "evm" })),
    )
    .await;
    assert_ne!(
        second.json()["nonce"].as_str().expect("nonce"),
        nonce,
        "a second nonce must not repeat the first"
    );
}

#[pollster::test]
async fn a_solana_nonce_names_the_solana_cluster() {
    let (kit, _clock) = fixture();

    let fields = nonce(&kit, ALICE, "solana").await;
    assert_eq!(fields.chain_id, "mainnet-beta");
}

#[pollster::test]
async fn an_unknown_chain_is_refused() {
    let (kit, _clock) = fixture();

    let response = send_as(
        &kit,
        ALICE,
        Method::POST,
        "/v1/wallets/nonce",
        Some(&json!({ "chain": "bitcoin" })),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("validation-failed"),
        "{}",
        response.problem()
    );
}

// ---------------------------------------------------------------------------
// The happy paths

#[pollster::test]
async fn an_evm_signature_links_the_wallet_to_the_signed_in_account() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["chain"], json!("evm"));
    assert_eq!(
        body["address"]
            .as_str()
            .expect("address")
            .to_ascii_lowercase(),
        wallet.address(),
    );
    assert!(body["id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(
        body["linked_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );
}

#[pollster::test]
async fn the_linked_address_is_stored_eip55_checksummed() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(2);

    // The message names the address in lowercase — what a wallet that has
    // not run EIP-55 on it sends. The stored form must be the checksummed
    // one, so the same wallet reached two ways is stored once.
    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(&wallet.address().to_ascii_lowercase());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let stored = response.json()["address"]
        .as_str()
        .expect("address")
        .to_owned();
    assert_eq!(stored.to_ascii_lowercase(), wallet.address());
    assert_ne!(stored, wallet.address(), "the stored form is checksummed");
    assert_eq!(stored.len(), 42, "0x plus 40 hex characters: {stored}");
}

#[pollster::test]
async fn a_solana_signature_links_the_wallet_too() {
    let (kit, _clock) = fixture();
    let wallet = SolanaWallet::from_seed(7);

    let fields = nonce(&kit, ALICE, "solana").await;
    let message = fields.siws(wallet.address());
    let signature = wallet.sign(&message);

    let response = verify(&kit, ALICE, &verify_body("solana", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(response.json()["address"], json!(wallet.address()));
    assert_eq!(response.json()["chain"], json!("solana"));
}

#[pollster::test]
async fn the_list_shows_the_callers_wallets_and_the_delete_removes_one() {
    let (kit, _clock) = fixture();
    let evm = EvmWallet::from_seed(1);
    let solana = SolanaWallet::from_seed(7);

    let evm_id = link_evm(&kit, ALICE, &evm).await;
    let solana_id = link_solana(&kit, ALICE, &solana).await;

    let listed = links(&list(&kit, ALICE).await.json());
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert!(listed.iter().any(|(id, chain, address)| {
        id == &evm_id && chain == "evm" && address.eq_ignore_ascii_case(evm.address())
    }));
    assert!(listed.contains(&(solana_id, "solana".to_owned(), solana.address().to_owned())));

    let unlinked = unlink(&kit, ALICE, &evm_id).await;
    assert_eq!(unlinked.status, StatusCode::OK, "{}", unlinked.text());
    assert_eq!(unlinked.json(), json!({ "ok": true }));

    let after = links(&list(&kit, ALICE).await.json());
    assert_eq!(after.len(), 1, "{after:?}");
    assert_eq!(after[0].2, solana.address());

    // Deleting it again finds nothing: the row is gone, not merely hidden.
    assert_eq!(
        unlink(&kit, ALICE, &evm_id).await.status,
        StatusCode::NOT_FOUND
    );
}

#[pollster::test]
async fn reverifying_a_wallet_this_account_already_holds_is_idempotent() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    let first = link_evm(&kit, ALICE, &wallet).await;
    let second = link_evm(&kit, ALICE, &wallet).await;
    assert_eq!(first, second, "the same wallet is one link, not two");
    assert_eq!(links(&list(&kit, ALICE).await.json()).len(), 1);
}

#[pollster::test]
async fn a_signature_from_the_wrong_wallet_is_refused() {
    let (kit, _clock) = fixture();
    let signer = EvmWallet::from_seed(1);
    let impostor = EvmWallet::from_seed(2);

    let fields = nonce(&kit, ALICE, "evm").await;
    // The message names one address and another key signs it.
    let message = fields.siwe(impostor.address());
    let signature = signer.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/signature-invalid"),
        "{}",
        response.problem()
    );
    assert!(links(&list(&kit, ALICE).await.json()).is_empty());
}

#[pollster::test]
async fn a_solana_signature_from_the_wrong_wallet_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = SolanaWallet::from_seed(7);
    let other = SolanaWallet::from_seed(9);

    let fields = nonce(&kit, ALICE, "solana").await;
    let message = fields.siws(wallet.address());
    let signature = other.sign(&message);

    let response = verify(&kit, ALICE, &verify_body("solana", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/signature-invalid"),
        "{}",
        response.problem()
    );
}

#[pollster::test]
async fn a_message_that_names_the_other_chain_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    // A perfectly good EVM proof presented as a Solana one.
    let response = verify(&kit, ALICE, &verify_body("solana", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/chain-mismatch"),
        "{}",
        response.problem()
    );
}

// ---------------------------------------------------------------------------
// Authentication

#[pollster::test]
async fn every_route_refuses_an_anonymous_caller() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);
    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);
    let body: Value = verify_body("evm", &message, &signature);

    let cases: [(Method, &str, Option<Value>); 4] = [
        (
            Method::POST,
            "/v1/wallets/nonce",
            Some(json!({ "chain": "evm" })),
        ),
        (Method::POST, "/v1/wallets/verify", Some(body)),
        (Method::GET, "/v1/wallets", None),
        (Method::DELETE, "/v1/wallets/anything", None),
    ];
    for (method, path, body) in cases {
        let response = send_anonymous(&kit, method.clone(), path, body.as_ref()).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: {}",
            response.text()
        );
        assert!(
            response.problem().ends_with("wallets/unauthenticated"),
            "{method} {path}: {}",
            response.problem()
        );
    }
}

#[pollster::test]
async fn a_deployment_where_nobody_signs_in_serves_nothing() {
    let clock = test_clock();
    let kit = kit(
        &Spec {
            anonymous: true,
            ..Spec::new()
        },
        &clock,
    );

    let response = send_as(
        &kit,
        ALICE,
        Method::POST,
        "/v1/wallets/nonce",
        Some(&json!({ "chain": "evm" })),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        response.text()
    );
}

// ---------------------------------------------------------------------------
// Helpers

/// Links `wallet` for `subject` and returns the new link's id.
async fn link_evm(kit: &TestHarness, subject: &str, wallet: &EvmWallet) -> String {
    let fields = nonce(kit, subject, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);
    let response = verify(kit, subject, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()["id"].as_str().expect("id").to_owned()
}

/// Links `wallet` for `subject` and returns the new link's id.
async fn link_solana(kit: &TestHarness, subject: &str, wallet: &SolanaWallet) -> String {
    let fields = nonce(kit, subject, "solana").await;
    let message = fields.siws(wallet.address());
    let signature = wallet.sign(&message);
    let response = verify(kit, subject, &verify_body("solana", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()["id"].as_str().expect("id").to_owned()
}
