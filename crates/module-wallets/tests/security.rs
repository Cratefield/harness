//! What the module refuses (issue #835): replay, a message bound to another
//! domain, an expired one, a wallet this account does not own, and — the
//! one that needs a chain but never reaches one — a smart-contract wallet
//! answered by an EIP-1271 verifier.
//!
//! The contract-wallet case runs entirely offline through
//! `StaticContractVerifier`, the no-network adapter the crate ships for it,
//! so the EIP-1271 path is proved without an RPC endpoint.

mod support;

use std::sync::Arc;

use axum::http::StatusCode;
use cratefield_module_wallets::{ContractSignatureVerifier, StaticContractVerifier};
use cratefield_testing::TestHarness;
use serde_json::json;
use time::Duration;

use support::{
    ALICE, BOB, EvmWallet, RecordingVerifier, SolanaWallet, Spec, advance, eip191_hash, fixture,
    kit, links, list, nonce, now, raw_keccak, test_clock, unlink, verify, verify_body,
    verify_concurrently,
};

/// The EIP-1271 magic return value a contract ends its `isValidSignature`
/// answer with: `0x1626ba7e`. A signature that starts with it is a contract
/// wallet's, never an EOA's, and is what falls through to the verifier.
const EIP_1271_MAGIC: &str = "1626ba7e";

/// A contract address that is a well-formed EVM address but has no key
/// behind it — a Safe, a Gnosis multisig, a smart account.
const CONTRACT: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";

// ---------------------------------------------------------------------------
// Replay

#[pollster::test]
async fn a_nonce_cannot_be_used_twice() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);
    let body = verify_body("evm", &message, &signature);

    let first = verify(&kit, ALICE, &body).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());

    // The exact same message and signature, the second time.
    let replay = verify(&kit, ALICE, &body).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST, "{}", replay.text());
    assert!(
        replay.problem().ends_with("wallets/nonce-invalid"),
        "{}",
        replay.problem()
    );

    // And the replay changed nothing: still one link, not two.
    assert_eq!(links(&list(&kit, ALICE).await.json()).len(), 1);
}

#[pollster::test]
async fn a_nonce_spent_by_two_concurrent_verifies_is_spent_once() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    // The nonce consume is a guarded `UPDATE … WHERE consumed_at IS NULL`,
    // so the row count is what decides the winner. One-at-a-time replay is
    // covered above; this fires both requests together, because that is the
    // case the guard exists for.
    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);
    let body = verify_body("evm", &message, &signature);

    let responses = verify_concurrently(&kit, ALICE, &body, 2).await;

    let winners: Vec<_> = responses
        .iter()
        .filter(|res| res.status == StatusCode::OK)
        .collect();
    let losers: Vec<_> = responses
        .iter()
        .filter(|res| res.status != StatusCode::OK)
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one verify wins the nonce: {:?}",
        responses.iter().map(|r| r.status).collect::<Vec<_>>()
    );
    assert_eq!(losers.len(), 1);
    for loser in &losers {
        assert_eq!(loser.status, StatusCode::BAD_REQUEST, "{}", loser.text());
        assert!(
            loser.problem().ends_with("wallets/nonce-invalid"),
            "the loser is told the nonce is gone: {}",
            loser.problem()
        );
    }

    // And the race produced one link, not two.
    let linked = links(&list(&kit, ALICE).await.json());
    assert_eq!(linked.len(), 1, "{linked:?}");
    assert_eq!(
        linked[0].2.to_ascii_lowercase(),
        wallet.address().to_ascii_lowercase()
    );
}

#[pollster::test]
async fn a_nonce_that_never_reached_its_owner_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    // Alice's nonce, spent by Bob: the signature is perfect, the session is
    // the wrong one.
    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, BOB, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/nonce-invalid"),
        "{}",
        response.problem()
    );
    // The nonce survives: a refused attempt does not burn it, so Alice can
    // still use her own.
    assert!(
        verify(&kit, ALICE, &verify_body("evm", &message, &signature))
            .await
            .status
            .is_success()
    );
}

#[pollster::test]
async fn a_nonce_the_server_never_minted_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    let mut fields = nonce(&kit, ALICE, "evm").await;
    fields.nonce = "NOTAMINTEDNONCE".to_owned();
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/nonce-invalid"),
        "{}",
        response.problem()
    );
}

#[pollster::test]
async fn a_nonce_minted_for_the_other_chain_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    // The message names the right chain id for an EVM verify, so the chain-id
    // check passes and what refuses it is the nonce row's own `chain`.
    let fields = nonce(&kit, ALICE, "solana").await.with_chain_id("1");
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/nonce-invalid"),
        "the nonce row carries its chain: {}",
        response.problem()
    );
}

#[pollster::test]
async fn a_lapsed_nonce_is_refused() {
    let clock = test_clock();
    let kit = kit(
        &Spec {
            nonce_ttl: Some(Duration::seconds(60)),
            ..Spec::new()
        },
        &clock,
    );
    let wallet = EvmWallet::from_seed(1);

    // The message outlives the nonce, so the nonce is what refuses it and
    // the refusal is about the nonce rather than about the message.
    let fields = nonce(&kit, ALICE, "evm")
        .await
        .expired_at(now(&clock) + Duration::hours(1));
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    advance(&clock, 61);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/nonce-invalid"),
        "{}",
        response.problem()
    );
    assert!(links(&list(&kit, ALICE).await.json()).is_empty());
}

// ---------------------------------------------------------------------------
// Domain binding

#[pollster::test]
async fn a_message_bound_to_another_domain_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    // A real nonce, a real signature — over a message that says this
    // wallet.test is asking when it is somebody else. This is the phishing
    // shape, and it must not verify here.
    let fields = nonce(&kit, ALICE, "evm").await.with_domain("evil.test");
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/domain-mismatch"),
        "{}",
        response.problem()
    );
    assert!(links(&list(&kit, ALICE).await.json()).is_empty());
}

#[pollster::test]
async fn a_solana_message_bound_to_another_domain_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = SolanaWallet::from_seed(7);

    let fields = nonce(&kit, ALICE, "solana").await.with_domain("evil.test");
    let message = fields.siws(wallet.address());
    let signature = wallet.sign(&message);

    let response = verify(&kit, ALICE, &verify_body("solana", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/domain-mismatch"),
        "{}",
        response.problem()
    );
}

// ---------------------------------------------------------------------------
// Expiry

#[pollster::test]
async fn an_expired_message_is_refused() {
    let clock = test_clock();
    let kit = kit(&Spec::new(), &clock);
    let wallet = EvmWallet::from_seed(1);

    let fields = nonce(&kit, ALICE, "evm").await;
    // The nonce is fresh, the signature is good, the message has expired.
    let fields = fields.expired_at(now(&clock) - Duration::hours(1));
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/message-expired"),
        "{}",
        response.problem()
    );
    assert!(links(&list(&kit, ALICE).await.json()).is_empty());
}

#[pollster::test]
async fn a_message_that_is_not_valid_yet_is_refused() {
    let clock = test_clock();
    let kit = kit(&Spec::new(), &clock);
    let wallet = EvmWallet::from_seed(1);

    let fields = nonce(&kit, ALICE, "evm")
        .await
        .valid_from(now(&clock) + Duration::hours(1));
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/message-expired"),
        "{}",
        response.problem()
    );
}

#[pollster::test]
async fn a_message_that_expires_while_the_person_reads_is_refused() {
    let clock = test_clock();
    let kit = kit(
        &Spec {
            nonce_ttl: Some(Duration::seconds(600)),
            ..Spec::new()
        },
        &clock,
    );
    let wallet = EvmWallet::from_seed(1);

    let fields = nonce(&kit, ALICE, "evm").await;
    // The message asks to be valid for half a minute and the nonce for ten
    // minutes, so it is the message's own `Expiration Time` that refuses
    // it — not the nonce, which is still good.
    let fields = fields.expired_at(now(&clock) + Duration::seconds(30));
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    advance(&clock, 31);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/message-expired"),
        "{}",
        response.problem()
    );
    assert!(links(&list(&kit, ALICE).await.json()).is_empty());
}

// ---------------------------------------------------------------------------
// Contract wallets (EIP-1271)

#[pollster::test]
async fn a_contract_wallet_is_accepted_through_the_eip1271_verifier() {
    let clock = test_clock();
    let kit = kit(
        &Spec {
            contract_verifier: Some(Arc::new(StaticContractVerifier::approving(
                CONTRACT.to_owned(),
            ))),
            ..Spec::new()
        },
        &clock,
    );

    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(CONTRACT);
    // A contract wallet's answer: the EIP-1271 magic value, never a 65-byte
    // `r || s || v` an EOA could produce.
    let signature = contract_signature();

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    assert_eq!(body["chain"], json!("evm"));
    assert_eq!(
        body["address"]
            .as_str()
            .expect("address")
            .to_ascii_lowercase(),
        CONTRACT.to_ascii_lowercase(),
    );
}

#[pollster::test]
async fn a_contract_wallet_the_verifier_does_not_recognise_is_refused() {
    let clock = test_clock();
    // The verifier approves one address; this kit's contract is another.
    let other = "0xde709f2102306220921060314715629080e2fb77";
    let kit = kit(
        &Spec {
            contract_verifier: Some(Arc::new(StaticContractVerifier::approving(
                other.to_owned(),
            ))),
            ..Spec::new()
        },
        &clock,
    );

    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(CONTRACT);
    let response = verify(
        &kit,
        ALICE,
        &verify_body("evm", &message, &contract_signature()),
    )
    .await;
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
async fn without_a_verifier_a_contract_wallet_is_refused_rather_than_hanging() {
    let (kit, _clock) = fixture();

    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(CONTRACT);
    let response = verify(
        &kit,
        ALICE,
        &verify_body("evm", &message, &contract_signature()),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/signature-invalid"),
        "an EOA-only deployment says so rather than calling a chain: {}",
        response.problem()
    );
}

// ---------------------------------------------------------------------------
// Chain-id binding
//
// The `chain` field only names a family ("evm"), so on its own it does not
// say which chain a message was written for. A message minted for one chain
// and presented to another is the same phishing shape as a message minted for
// another domain, and it matters most on the EIP-1271 path, where the chain id
// decides which chain the verifier is asked about.

#[pollster::test]
async fn an_evm_message_for_another_chain_id_is_refused() {
    let clock = test_clock();
    let kit = kit(
        &Spec {
            chain_id: "1".to_owned(),
            ..Spec::new()
        },
        &clock,
    );
    let wallet = EvmWallet::from_seed(1);

    // A real nonce minted here, a real signature over the message — a message
    // that says it is for chain 1337 while this service is chain 1.
    let fields = nonce(&kit, ALICE, "evm").await.with_chain_id("1337");
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/chain-mismatch"),
        "a cross-chain message is refused: {}",
        response.problem()
    );
    assert!(links(&list(&kit, ALICE).await.json()).is_empty());
}

#[pollster::test]
async fn a_solana_message_for_another_cluster_is_refused() {
    let (kit, _clock) = fixture();
    let wallet = SolanaWallet::from_seed(7);

    // This service mints `mainnet-beta`; a message naming `devnet` is for a
    // different chain and is refused even though the signature is perfect.
    let fields = nonce(&kit, ALICE, "solana").await.with_chain_id("devnet");
    let message = fields.siws(wallet.address());
    let signature = wallet.sign(&message);

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
    assert!(links(&list(&kit, ALICE).await.json()).is_empty());
}

#[pollster::test]
async fn a_non_mainnet_configuration_accepts_only_its_own_chain_id() {
    let clock = test_clock();
    let kit = kit(
        &Spec {
            chain_id: "8453".to_owned(),
            ..Spec::new()
        },
        &clock,
    );
    let wallet = EvmWallet::from_seed(1);

    // The configured chain is accepted...
    let fields = nonce(&kit, ALICE, "evm").await.with_chain_id("8453");
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);
    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    // ...and mainnet, which the same code would have accepted before the
    // chain id was checked at all, is not.
    let fields = nonce(&kit, BOB, "evm").await.with_chain_id("1");
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);
    let response = verify(&kit, BOB, &verify_body("evm", &message, &signature)).await;
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

#[pollster::test]
async fn a_cross_chain_message_never_reaches_the_contract_verifier() {
    let clock = test_clock();
    let verifier = RecordingVerifier::new(CONTRACT);
    let kit = kit(
        &Spec {
            chain_id: "1".to_owned(),
            contract_verifier: Some(Arc::new(verifier.clone())),
            ..Spec::new()
        },
        &clock,
    );

    let fields = nonce(&kit, ALICE, "evm").await.with_chain_id("10");
    let message = fields.siwe(CONTRACT);
    let response = verify(
        &kit,
        ALICE,
        &verify_body("evm", &message, &contract_signature()),
    )
    .await;

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
    assert!(
        verifier.calls().is_empty(),
        "the verifier is never asked about a chain the message chose: {:?}",
        verifier.calls()
    );
}

#[pollster::test]
async fn the_contract_verifier_is_asked_about_this_services_chain_and_no_other() {
    let clock = test_clock();
    let verifier = RecordingVerifier::new(CONTRACT);
    let kit = kit(
        &Spec {
            chain_id: "8453".to_owned(),
            contract_verifier: Some(Arc::new(verifier.clone())),
            ..Spec::new()
        },
        &clock,
    );

    let fields = nonce(&kit, ALICE, "evm").await.with_chain_id("8453");
    let message = fields.siwe(CONTRACT);
    let response = verify(
        &kit,
        ALICE,
        &verify_body("evm", &message, &contract_signature()),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    // An `eth_call` verifier turns this string into an RPC target, so it must
    // be the server's chain, never the message's.
    let call = verifier.only_call();
    assert_eq!(call.chain_id, "8453");
    assert_eq!(
        call.address.to_ascii_lowercase(),
        CONTRACT.to_ascii_lowercase()
    );
}

#[pollster::test]
async fn the_contract_verifier_is_asked_about_the_eip191_hash_of_the_message() {
    let clock = test_clock();
    let verifier = RecordingVerifier::new(CONTRACT);
    let kit = kit(
        &Spec {
            contract_verifier: Some(Arc::new(verifier.clone())),
            ..Spec::new()
        },
        &clock,
    );

    let fields = nonce(&kit, ALICE, "evm").await;
    let message = fields.siwe(CONTRACT);
    let signature = contract_signature();
    let response = verify(&kit, ALICE, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());

    let call = verifier.only_call();
    assert_eq!(
        call.message_hash,
        eip191_hash(&message),
        "the EIP-1271 call carries the personal-sign hash of the exact bytes signed"
    );
    assert_eq!(
        call.signature,
        hex::decode(&signature).expect("hex signature")
    );
}

#[test]
fn the_shipped_static_verifier_is_pinned_to_one_message_hash() {
    // The route-level hash binding is proved above through the recording
    // double. This covers the adapter the crate actually ships:
    // `StaticContractVerifier::new` must pin the EIP-191 hash, so feeding it
    // a raw keccak of the same bytes would not pass.
    let pinned = StaticContractVerifier::new(CONTRACT.to_owned(), "the message");
    assert_eq!(
        pollster::block_on(pinned.is_valid_signature(
            "1",
            CONTRACT,
            eip191_hash("the message"),
            &[]
        )),
        Ok(true),
        "the hash it was built for is accepted"
    );
    assert_eq!(
        pollster::block_on(pinned.is_valid_signature(
            "1",
            CONTRACT,
            raw_keccak("the message"),
            &[]
        )),
        Ok(false),
        "a raw keccak of the same bytes is not the personal-sign hash"
    );
    assert_eq!(
        pollster::block_on(pinned.is_valid_signature(
            "1",
            CONTRACT,
            eip191_hash("another message"),
            &[]
        )),
        Ok(false),
        "and so is another message's hash"
    );
}

// ---------------------------------------------------------------------------
// One wallet, one account

#[pollster::test]
async fn a_wallet_links_to_the_person_who_proved_it_and_to_nobody_else() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);

    let id = link_evm(&kit, ALICE, &wallet).await;

    // Alice sees it.
    let mine = links(&list(&kit, ALICE).await.json());
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0].0, id);

    // Bob sees nothing — not the wallet, not the address, not the row.
    let theirs = list(&kit, BOB).await;
    assert_eq!(theirs.status, StatusCode::OK);
    assert!(
        links(&theirs.json()).is_empty(),
        "one account's wallets are not another's: {}",
        theirs.text()
    );
}

#[pollster::test]
async fn bob_cannot_take_over_a_wallet_alice_already_linked() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);
    link_evm(&kit, ALICE, &wallet).await;

    // Bob does hold the key and does produce a valid signature over a fresh
    // nonce of his own. What he has not got is Alice's link — and a
    // signature proves ownership of an address, never of an account's row.
    let fields = nonce(&kit, BOB, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);

    let response = verify(&kit, BOB, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text());
    assert!(
        response
            .problem()
            .ends_with("wallets/address-already-linked"),
        "{}",
        response.problem()
    );

    // Alice's row is untouched, and Bob still has nothing.
    assert_eq!(links(&list(&kit, ALICE).await.json()).len(), 1);
    assert!(links(&list(&kit, BOB).await.json()).is_empty());
}

#[pollster::test]
async fn bob_cannot_unlink_alices_wallet() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);
    let id = link_evm(&kit, ALICE, &wallet).await;

    let response = unlink(&kit, BOB, &id).await;
    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "{}",
        response.text()
    );
    assert!(
        response.problem().ends_with("wallets/not-found"),
        "{}",
        response.problem()
    );

    // Alice's wallet is still there.
    assert_eq!(links(&list(&kit, ALICE).await.json()).len(), 1);
}

#[pollster::test]
async fn a_wallet_survives_being_linked_again_by_the_same_account() {
    let (kit, _clock) = fixture();
    let wallet = EvmWallet::from_seed(1);
    let first = link_evm(&kit, ALICE, &wallet).await;
    let second = link_evm(&kit, ALICE, &wallet).await;
    assert_eq!(first, second);
    assert_eq!(links(&list(&kit, ALICE).await.json()).len(), 1);
}

// ---------------------------------------------------------------------------
// Helpers

/// A contract wallet's `isValidSignature` return value, hex with no
/// prefix: the four magic bytes plus a payload, which is enough to be
/// unambiguously not a 65-byte EOA signature.
fn contract_signature() -> String {
    let mut signature = String::from(EIP_1271_MAGIC);
    for _ in 0..4 {
        signature.push_str("deadbeef");
    }
    signature
}

/// Links `wallet` for `subject` and returns the new link's id.
async fn link_evm(kit: &TestHarness, subject: &str, wallet: &EvmWallet) -> String {
    let fields = nonce(kit, subject, "evm").await;
    let message = fields.siwe(wallet.address());
    let signature = wallet.sign_personal(&message);
    let response = verify(kit, subject, &verify_body("evm", &message, &signature)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()["id"].as_str().expect("id").to_owned()
}
