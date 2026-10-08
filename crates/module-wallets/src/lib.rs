//! Linking a person's own crypto wallet to an account they have already
//! signed in to, over a signature rather than a password (issue #835).
//!
//! The module proves two things and refuses everything else:
//!
//! - that the caller controls the address in the message, by verifying an
//!   EIP-191 `personal_sign` signature on an EIP-4361 (SIWE) message or an
//!   ed25519 signature on a SIWS message; and
//! - that the caller is already signed in, through the `Auth` port, because
//!   a wallet signature on its own proves nothing about who is holding the
//!   browser.
//!
//! The proof is a single-use nonce the module itself minted and bound to the
//! caller's account, so a message signed once cannot be replayed and a
//! signature captured on one site cannot be presented to another (the
//! message is also bound to `domain`).
//!
//! **This module never asks a wallet to move funds.** It reads an address
//! and proves ownership of it. No approval, allowance or spending flow of
//! any kind appears anywhere in the crate, and no transaction of any kind is
//! ever requested — a wallet connection that could spend is a different,
//! much larger module, and it is not this one.
//!
//! # The two chains
//!
//! - **EVM** — the signature is a 65-byte `r || s || v` that recovers a
//!   secp256k1 public key, whose keccak-256 tail is the address. A
//!   smart-contract wallet cannot produce such a signature, so anything that
//!   does not recover the address in the message falls through to a
//!   [`ContractSignatureVerifier`] — the EIP-1271 `isValidSignature` hook —
//!   which also carries EIP-6492 counterfactual signatures.
//! - **Solana** — the address is a base58 32-byte ed25519 public key and the
//!   signature is verified over the exact message bytes, with no
//!   EIP-191 prefix: a SIWS message is signed verbatim.
//!
//! A contract-wallet verifier is optional. Without one the module serves
//! EOAs only, which is a smaller module, not a broken one — a contract
//! address simply fails the check.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod crypto;
mod handlers;
mod store;

use std::sync::{Arc, OnceLock};

use time::Duration;

use cratefield_core::{
    Action, AnyError, Audience, BoxFuture, Config, ConfigError, DataKind, Disposition, Migrations,
    Module, ModuleContext, Outcome, PersonalDataSet, Port, RandomBytes, RoutePolicy, SqlMigration,
    Surface,
};

pub use crypto::{
    AddressError, ContractSignatureVerifier, ContractVerifierError, MessageError,
    StaticContractVerifier, VerifyError,
};

/// How long a nonce stays usable by default: ten minutes. Long enough to
/// find the wallet and read the message, short enough that a nonce captured
/// from a log or a referrer is dead before anyone could use it.
pub const DEFAULT_NONCE_TTL: Duration = Duration::seconds(600);

/// The EVM chain id the module asks a wallet to sign against when the
/// composition names none — Ethereum mainnet, the one a message written for
/// "the chain" almost always means.
pub const DEFAULT_EVM_CHAIN_ID: &str = "1";

/// The Solana chain id SIWS messages carry. Solana has one cluster id and
/// names it this; the module never varies it.
pub const SOLANA_CHAIN_ID: &str = "mainnet-beta";

/// The SIWE/SIWS `Version` field, fixed by EIP-4361 and its Solana twin.
pub const MESSAGE_VERSION: &str = "1";

/// The module's one migration: the `wallet_nonces` and `wallet_links`
/// tables in the portable SQL subset (ADR 0004).
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

// ---------------------------------------------------------------------------
// Chains

/// Which chain a wallet lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// An EVM account: secp256k1, EIP-191 `personal_sign`, EIP-4361 SIWE.
    Evm,
    /// A Solana account: ed25519, verbatim message signing, SIWS.
    Solana,
}

/// Why a chain name was not understood.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown chain {0:?}: expected \"evm\" or \"solana\"")]
pub struct UnknownChain(pub String);

impl Chain {
    /// The wire name of this chain: what a request body says.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Solana => "solana",
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The chain a request named, or an error naming what was expected.
impl std::str::FromStr for Chain {
    type Err = UnknownChain;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "evm" => Ok(Self::Evm),
            "solana" => Ok(Self::Solana),
            other => Err(UnknownChain(other.to_owned())),
        }
    }
}

// ---------------------------------------------------------------------------
// The module and its builder

/// Linking a person's own EVM or Solana wallet to their signed-in account.
pub struct Wallets {
    settings: handlers::Settings,
}

impl Default for Wallets {
    fn default() -> Self {
        Self::new()
    }
}

impl Wallets {
    /// A builder with no domain and no entropy source — not a working
    /// composition until `.domain(..)` and `.random(..)` are set;
    /// [`Module::self_check`] names what is missing.
    #[must_use]
    pub fn builder() -> WalletsBuilder {
        WalletsBuilder::new()
    }

    /// Short for [`Wallets::builder().build()`](Wallets::builder).
    #[must_use]
    pub fn new() -> Self {
        WalletsBuilder::new().build()
    }
}

/// Builds a [`Wallets`]. Everything the module cannot decide for a venture —
/// which domain its messages are bound to, where its entropy comes from,
/// whether it can check a contract wallet — is set here.
pub struct WalletsBuilder {
    settings: handlers::Settings,
}

impl Default for WalletsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletsBuilder {
    /// The defaults: no domain, no entropy source, Ethereum mainnet, a
    /// ten-minute nonce and no contract verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: handlers::Settings {
                domain: String::new(),
                uri: String::new(),
                statement: None,
                version: MESSAGE_VERSION.to_owned(),
                chain_id_evm: DEFAULT_EVM_CHAIN_ID.to_owned(),
                chain_id_solana: SOLANA_CHAIN_ID.to_owned(),
                nonce_ttl_secs: DEFAULT_NONCE_TTL.whole_seconds(),
                random: None,
                contract_verifier: None,
            },
        }
    }

    /// The domain every SIWE/SIWS message must name. This is the
    /// phishing defence, so it is required: a message minted for another
    /// site is refused rather than verified.
    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.settings.domain = domain.into();
        self
    }

    /// The `URI` field of the messages, the page the signer is being sent
    /// back to. Defaults to `https://<domain>`.
    #[must_use]
    pub fn uri(mut self, uri: impl Into<String>) -> Self {
        self.settings.uri = uri.into();
        self
    }

    /// The `Statement` line — the words the person reads before signing.
    /// This is the one line that reaches a human, so it should say what is
    /// about to happen in the plainest words available.
    #[must_use]
    pub fn statement(mut self, statement: impl Into<String>) -> Self {
        self.settings.statement = Some(statement.into());
        self
    }

    /// The EVM chain id the messages carry. Defaults to
    /// [`DEFAULT_EVM_CHAIN_ID`].
    #[must_use]
    pub fn chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.settings.chain_id_evm = chain_id.into();
        self
    }

    /// How long a nonce stays usable. Clamped to at least one second and at
    /// most [`MAX_NONCE_TTL`].
    #[must_use]
    pub fn nonce_ttl(mut self, ttl: Duration) -> Self {
        self.settings.nonce_ttl_secs = ttl.whole_seconds().clamp(1, MAX_NONCE_TTL.whole_seconds());
        self
    }

    /// Sets the entropy source nonces are drawn from. Required: core
    /// carries no CSPRNG, so the venture supplies one (ADR 0002).
    #[must_use]
    pub fn random(mut self, random: impl RandomBytes + 'static) -> Self {
        self.settings.random = Some(Arc::new(random));
        self
    }

    /// Sets the EIP-1271 contract-wallet verifier. Left unset the module
    /// serves EOAs only; a smart-contract wallet then fails with
    /// `wallets/signature-invalid` rather than hanging on a chain call.
    #[must_use]
    pub fn contract_verifier(mut self, verifier: impl ContractSignatureVerifier + 'static) -> Self {
        self.settings.contract_verifier = Some(Arc::new(verifier));
        self
    }

    /// Builds the module. A blank `uri` with a domain set becomes
    /// `https://<domain>`, so the common composition does not have to
    /// repeat the domain twice.
    #[must_use]
    pub fn build(mut self) -> Wallets {
        if self.settings.uri.is_empty() && !self.settings.domain.is_empty() {
            self.settings.uri = format!("https://{}", self.settings.domain);
        }
        Wallets {
            settings: self.settings,
        }
    }
}

/// The longest a nonce may live: one hour. A proof of ownership that is
/// still good after that is a proof somebody kept.
pub const MAX_NONCE_TTL: Duration = Duration::seconds(60 * 60);

impl Module for Wallets {
    fn name(&self) -> &'static str {
        "wallets"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Nonces and links live in the database, and every route answers only
    /// to a signed-in caller — a wallet signature proves ownership of an
    /// address, never of a session.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Auth]
    }

    /// The `Clock` decides "now" for nonce and message expiry. The `IdGen`
    /// names each link; without one the handler falls back to a derived id.
    fn optional(&self) -> &'static [Port] {
        &[Port::Clock, Port::IdGen]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["wallet_nonces", "wallet_links"]
    }

    /// Two subject-owned datasets, one per table.
    ///
    /// `wallet_nonces` is an attempt in flight: who asked for a nonce, for
    /// which chain, and when it lapsed. It says nothing about a wallet —
    /// the address arrives in the signed message, and the row is deleted
    /// once it expires whether or not it was ever spent.
    ///
    /// `wallet_links` is the durable one: the address a person proved they
    /// control, the chain it lives on and when it was linked. It is
    /// `Erase`, because a person who deletes their account expects the
    /// wallet they linked to it to go with it — a wallet address is a
    /// durable identifier, not a receipt.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        static SETS: OnceLock<Vec<PersonalDataSet>> = OnceLock::new();
        SETS.get_or_init(|| {
            vec![
                PersonalDataSet {
                    table: "wallet_nonces",
                    subject: "account_id",
                    kind: DataKind::Identifier,
                    disposition: Disposition::Erase,
                    description: "An outstanding single-use proof-of-ownership nonce: who \
                        requested it, which chain it was for, when it was issued and when it \
                        lapsed. The address it is eventually spent against is never stored \
                        here — it is in the signed message, not the row. Erasing the subject's \
                        rows deletes them; the scheduled purge removes every row past its \
                        expiry anyway, spent or not.",
                    redacted: &[],
                    subject_via: None,
                },
                PersonalDataSet {
                    table: "wallet_links",
                    subject: "account_id",
                    kind: DataKind::Identifier,
                    disposition: Disposition::Erase,
                    description: "A wallet the subject proved they control: the checksummed \
                        address, the chain it lives on, and when it was linked. The module \
                        stores no signature and no signature hash, so a row cannot be replayed \
                        as a proof of anything. Erasing the subject's rows deletes every wallet \
                        they linked.",
                    redacted: &[],
                    subject_via: None,
                },
            ]
        })
        .as_slice()
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    /// No configuration keys of its own: the composition is what a venture
    /// decides, and `self_check` reports a composition that cannot verify a
    /// single signature.
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn self_check(&self) -> Vec<String> {
        handlers::self_check(&self.settings)
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(ctx, self.settings.clone())
    }

    /// The four routes, all [`Audience::Subject`].
    ///
    /// They are [`RoutePolicy::Open`] at the gateway and authenticate
    /// themselves, deliberately: the proof here is not a signed link or a
    /// CAPTCHA but a signature over a message the caller had to be signed
    /// in to fetch, and a CAPTCHA on a `POST` from a wallet extension
    /// would be a widget nobody can solve. The handlers refuse an
    /// anonymous or unidentified caller before touching a byte of body,
    /// and `Port::Auth` is required, so a deployment cannot mount these
    /// without a way to identify callers at all.
    fn surface(&self) -> Surface {
        Surface::new()
            .action(
                Action::post("nonce", "/nonce")
                    .policy(RoutePolicy::Open)
                    .audience(Audience::Subject)
                    .outcome(Outcome::Json)
                    .input_schema(cratefield_core::schema_for::<handlers::NonceBody>())
                    .output::<handlers::NonceResponse>(),
            )
            .action(
                Action::post("verify", "/verify")
                    .policy(RoutePolicy::Open)
                    .audience(Audience::Subject)
                    .outcome(Outcome::Json)
                    .input_schema(cratefield_core::schema_for::<handlers::VerifyBody>())
                    .output::<handlers::LinkResponse>(),
            )
            .action(
                Action::get("list", "/")
                    .policy(RoutePolicy::Open)
                    .audience(Audience::Subject)
                    .outcome(Outcome::Json),
            )
            .action(
                Action::delete("unlink", "/{id}")
                    .policy(RoutePolicy::Open)
                    .audience(Audience::Subject),
            )
    }

    /// The scheduled purge: nonces past their expiry are deleted, spent or
    /// not. A spent nonce is already useless, and a lapsed one is the only
    /// kind worth reclaiming — leaving them would let the table grow without
    /// bound and leave rows describing when each account was trying to
    /// connect a wallet. One statement, so it spends one unit of the
    /// invocation's budget (ADR 0023).
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            if !ctx.scheduled.try_spend(1) {
                return Ok(());
            }
            let Some(db) = ctx.ports.db.clone() else {
                return Ok(());
            };
            let now = handlers::stamp(handlers::now_of(ctx));
            let deleted = store::purge_expired_nonces(&*db, &now)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if deleted > 0 {
                tracing::info!(deleted, cron, "purged expired wallet nonces");
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() -> Wallets {
        Wallets::builder().domain("example.test").build()
    }

    #[test]
    fn module_metadata() {
        let module = module();
        assert_eq!(module.name(), "wallets");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.requires(), [Port::Db, Port::Auth]);
        assert_eq!(module.optional(), [Port::Clock, Port::IdGen]);
        assert_eq!(module.tables(), ["wallet_nonces", "wallet_links"]);
        assert_eq!(module.migrations().sqlite.len(), 1);
        assert!(
            module.migrations().postgres.is_empty(),
            "sqlite migrations only"
        );
        assert!(!module.surface().is_empty());
    }

    #[test]
    fn the_defaults_are_a_ten_minute_nonce_on_mainnet() {
        let module = Wallets::new();
        assert_eq!(module.settings.nonce_ttl_secs, 600);
        assert_eq!(module.settings.chain_id_evm, "1");
        assert_eq!(module.settings.chain_id_solana, SOLANA_CHAIN_ID);
        assert_eq!(module.settings.version, "1");
        assert!(module.settings.statement.is_none());
        assert!(module.settings.contract_verifier.is_none());
    }

    #[test]
    fn the_builder_sets_what_it_names() {
        let module = Wallets::builder()
            .domain("example.test")
            .uri("https://example.test/connect")
            .statement("Link this wallet.")
            .chain_id("8453")
            .nonce_ttl(Duration::seconds(120))
            .build();
        assert_eq!(module.settings.domain, "example.test");
        assert_eq!(module.settings.uri, "https://example.test/connect");
        assert_eq!(
            module.settings.statement.as_deref(),
            Some("Link this wallet.")
        );
        assert_eq!(module.settings.chain_id_evm, "8453");
        assert_eq!(module.settings.nonce_ttl_secs, 120);
    }

    #[test]
    fn the_uri_defaults_to_the_domain() {
        let module = Wallets::builder().domain("example.test").build();
        assert_eq!(module.settings.uri, "https://example.test");
    }

    #[test]
    fn builder_values_are_clamped_not_honoured() {
        let module = Wallets::builder().nonce_ttl(Duration::ZERO).build();
        assert_eq!(module.settings.nonce_ttl_secs, 1);

        let module = Wallets::builder()
            .nonce_ttl(Duration::seconds(365 * 24 * 60 * 60))
            .build();
        assert_eq!(
            module.settings.nonce_ttl_secs,
            MAX_NONCE_TTL.whole_seconds()
        );
    }

    #[test]
    fn self_check_names_every_missing_piece() {
        let text = Wallets::new().self_check().join("\n");
        assert!(text.contains("no domain is set"), "{text}");
        assert!(text.contains("no entropy source is set"), "{text}");

        let text = Wallets::builder()
            .domain("example.test")
            .build()
            .self_check()
            .join("\n");
        assert!(!text.contains("no domain is set"), "{text}");
        assert!(text.contains("no entropy source is set"), "{text}");
    }

    #[test]
    fn a_chain_round_trips_through_its_wire_name() {
        assert_eq!("evm".parse::<Chain>().unwrap(), Chain::Evm);
        assert_eq!("solana".parse::<Chain>().unwrap(), Chain::Solana);
        assert_eq!(Chain::Evm.as_str(), "evm");
        assert_eq!(Chain::Solana.to_string(), "solana");
        assert_eq!(
            "EVM".parse::<Chain>().unwrap_err(),
            UnknownChain("EVM".to_owned())
        );
    }

    #[test]
    fn a_contract_verifier_makes_the_module_compose() {
        let module = Wallets::builder()
            .domain("example.test")
            .contract_verifier(StaticContractVerifier::new(
                "0x52908400098527886E0F7030069857D2E4169EE7".to_owned(),
                "a message",
            ))
            .build();
        assert!(module.settings.contract_verifier.is_some());
    }
}
