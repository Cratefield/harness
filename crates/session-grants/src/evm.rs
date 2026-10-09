//! The EVM side: the bundler+paymaster port (shaped after the `Pimlico`
//! and `ZeroDev` ERC-4337 endpoints), the JSON-RPC adapter those
//! endpoints are reached through, and the Kernel permission port — grant
//! through the permission validator, revoke through `uninstallPlugin`.

use serde::Deserialize;
use serde_json::json;

use crate::grant::{GrantSpec, OnChainBinding};
use crate::types::{Address, OwnerSignature};

/// The canonical ERC-4337 v0.7 entry point
/// (`0x5FF1...2789`), the address every bundler call names.
pub const ENTRY_POINT_V07: &str = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789";

/// An ERC-4337 v0.7 user operation. The u256 fields (`nonce`, gas prices)
/// are decimal strings, the byte fields `0x` hex, the field names the
/// camelCase the wire uses — the shapes the bundler endpoints speak, kept
/// so the crate needs no bignum.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperation {
    /// The account the operation executes from.
    pub sender: Address,
    /// The account's nonce, decimal string.
    pub nonce: String,
    /// The call data the account executes, `0x` hex.
    pub call_data: String,
    /// Gas for the call itself, decimal string.
    pub call_gas_limit: String,
    /// Gas for the account's verification, decimal string.
    pub verification_gas_limit: String,
    /// The constant overhead, decimal string.
    pub pre_verification_gas: String,
    /// The all-in gas price, decimal string.
    pub max_fee_per_gas: String,
    /// The priority fee, decimal string.
    pub max_priority_fee_per_gas: String,
    /// The paymaster sponsoring the operation, when one is set.
    pub paymaster: Option<Address>,
    /// The paymaster's context blob, `0x` hex.
    pub paymaster_data: String,
    /// The signature (the session key's, for a granted operation).
    pub signature: String,
}

impl UserOperation {
    /// An operation with zero gas and no paymaster: the caller fills in
    /// what the estimate (and then the sponsor call) returns.
    #[must_use]
    pub fn zero(sender: Address, call_data: String) -> Self {
        Self {
            sender,
            nonce: "0".to_owned(),
            call_data,
            call_gas_limit: "0".to_owned(),
            verification_gas_limit: "0".to_owned(),
            pre_verification_gas: "0".to_owned(),
            max_fee_per_gas: "0".to_owned(),
            max_priority_fee_per_gas: "0".to_owned(),
            paymaster: None,
            paymaster_data: String::new(),
            signature: String::new(),
        }
    }
}

/// What `eth_estimateUserOperationGas` returns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GasEstimate {
    /// Gas for the account's verification.
    pub verification_gas_limit: String,
    /// Gas for the call itself.
    pub call_gas_limit: String,
    /// The constant overhead.
    pub pre_verification_gas: String,
}

/// What the paymaster sponsorship call (`pm_sponsorUserOperation`)
/// returns: the paymaster context to merge into the operation, and often
/// tighter gas than the bare estimate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sponsorship {
    /// The `paymasterAndData` blob to set on the operation.
    pub paymaster_and_data: String,
    /// Gas for the account's verification, as sponsored.
    pub verification_gas_limit: String,
    /// Gas for the call itself, as sponsored.
    pub call_gas_limit: String,
    /// The constant overhead, as sponsored.
    pub pre_verification_gas: String,
}

/// What `eth_getUserOperationReceipt` returns, trimmed to what a grant
/// server records.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOpReceipt {
    /// The operation's hash.
    pub user_op_hash: String,
    /// The transaction that included it.
    pub transaction_hash: String,
    /// Whether the operation executed successfully.
    pub success: bool,
}

/// The user operation's hash, as the bundler assigned it.
pub type UserOpHash = String;

/// Why a bundler or paymaster call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BundlerError {
    /// The node answered with a JSON-RPC error object.
    #[error("the bundler rejected {method}: {code} {message}")]
    Rpc {
        /// The JSON-RPC method the error came from.
        method: &'static str,
        /// The error's code.
        code: i64,
        /// The error's message, redacted of anything the provider sent.
        message: String,
    },
    /// The transport under the JSON-RPC client failed.
    #[error("the transport failed on {method}: {message}")]
    Transport {
        /// The JSON-RPC method that was in flight.
        method: &'static str,
        /// What the transport reported.
        message: String,
    },
}

/// The JSON-RPC 2.0 transport the bundler client speaks over. The runtime
/// provides it (Workers `fetch`, native reqwest); the crate provides the
/// client and the method mapping, so a new provider is a new base URL.
#[async_trait::async_trait]
pub trait JsonRpcTransport: Send + Sync {
    /// Calls `method` with `params`, returning the result member —
    /// the error member becomes [`JsonRpcError`].
    ///
    /// # Errors
    /// [`JsonRpcError`] when the call fails at the protocol level or the
    /// transport fails underneath.
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError>;
}

/// A JSON-RPC error, with the method it came from.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{method}: {code} {message}")]
pub struct JsonRpcError {
    /// The method the error came from.
    pub method: String,
    /// The JSON-RPC error code.
    pub code: i64,
    /// The error message.
    pub message: String,
}

/// The bundler+paymaster port, shaped after the `Pimlico` and `ZeroDev`
/// ERC-4337 endpoints: the same five calls, the same fields, no vendor
/// `SDK`. `entry_point` is always [`ENTRY_POINT_V07`].
#[async_trait::async_trait]
pub trait Bundler: Send + Sync {
    /// The chain the bundler serves, from `eth_chainId`. A grant server
    /// checks this against the grant's chain before sending anything.
    ///
    /// # Errors
    /// [`BundlerError`] from the transport or the node.
    async fn chain_id(&self) -> Result<u64, BundlerError>;

    /// `eth_estimateUserOperationGas`.
    ///
    /// # Errors
    /// [`BundlerError`] from the transport or the node.
    async fn estimate_gas(&self, op: &UserOperation) -> Result<GasEstimate, BundlerError>;

    /// `pm_sponsorUserOperation`: ask the paymaster to sponsor, getting
    /// the gas limits and the context to merge into the operation.
    ///
    /// # Errors
    /// [`BundlerError`] from the transport or the node.
    async fn sponsor(&self, op: &UserOperation) -> Result<Sponsorship, BundlerError>;

    /// `eth_sendUserOperation`; returns the operation hash.
    ///
    /// # Errors
    /// [`BundlerError`] from the transport or the node.
    async fn send(&self, op: &UserOperation) -> Result<UserOpHash, BundlerError>;

    /// `eth_getUserOperationReceipt`; `None` while the operation is still
    /// in the mempool.
    ///
    /// # Errors
    /// [`BundlerError`] from the transport or the node.
    async fn receipt(&self, hash: &str) -> Result<Option<UserOpReceipt>, BundlerError>;
}

/// The bundler adapter: [`Bundler`] over any [`JsonRpcTransport`], with
/// the Pimlico/ZeroDev method names. This is the shape a real adapter
/// behind the runtime's `HttpClient` port fills in.
#[derive(Debug, Clone)]
pub struct BundlerClient<T: JsonRpcTransport> {
    transport: T,
    entry_point: Address,
}

impl<T: JsonRpcTransport> BundlerClient<T> {
    /// A client over `transport`, against the canonical v0.7 entry point.
    ///
    /// # Panics
    /// Never at a working checkout: the entry point literal is a fixed
    /// constant, and its parse is total.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            entry_point: Address::parse(ENTRY_POINT_V07).expect("a valid entry point literal"),
        }
    }

    /// The entry point every call names.
    #[must_use]
    pub fn entry_point(&self) -> &Address {
        &self.entry_point
    }

    /// The transport underneath, for a test or an operator to inspect
    /// what went out.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Maps a transport failure onto the port error.
    fn transport_error(method: &'static str, error: &JsonRpcError) -> BundlerError {
        BundlerError::Transport {
            method,
            message: error.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl<T: JsonRpcTransport> Bundler for BundlerClient<T> {
    async fn chain_id(&self) -> Result<u64, BundlerError> {
        const METHOD: &str = "eth_chainId";
        let value = self
            .transport
            .call(METHOD, json!([]))
            .await
            .map_err(|error| Self::transport_error(METHOD, &error))?;
        let text: String =
            serde_json::from_value(value).map_err(|error| BundlerError::Transport {
                method: METHOD,
                message: error.to_string(),
            })?;
        u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|error| {
            BundlerError::Transport {
                method: METHOD,
                message: error.to_string(),
            }
        })
    }

    async fn estimate_gas(&self, op: &UserOperation) -> Result<GasEstimate, BundlerError> {
        const METHOD: &str = "eth_estimateUserOperationGas";
        let value = self
            .transport
            .call(METHOD, json!([op, self.entry_point]))
            .await
            .map_err(|error| Self::transport_error(METHOD, &error))?;
        serde_json::from_value(value).map_err(|error| BundlerError::Transport {
            method: METHOD,
            message: error.to_string(),
        })
    }

    async fn sponsor(&self, op: &UserOperation) -> Result<Sponsorship, BundlerError> {
        const METHOD: &str = "pm_sponsorUserOperation";
        let value = self
            .transport
            .call(METHOD, json!([op, self.entry_point]))
            .await
            .map_err(|error| Self::transport_error(METHOD, &error))?;
        serde_json::from_value(value).map_err(|error| BundlerError::Transport {
            method: METHOD,
            message: error.to_string(),
        })
    }

    async fn send(&self, op: &UserOperation) -> Result<UserOpHash, BundlerError> {
        const METHOD: &str = "eth_sendUserOperation";
        let value = self
            .transport
            .call(METHOD, json!([op, self.entry_point]))
            .await
            .map_err(|error| Self::transport_error(METHOD, &error))?;
        serde_json::from_value(value).map_err(|error| BundlerError::Transport {
            method: METHOD,
            message: error.to_string(),
        })
    }

    async fn receipt(&self, hash: &str) -> Result<Option<UserOpReceipt>, BundlerError> {
        const METHOD: &str = "eth_getUserOperationReceipt";
        let value = self
            .transport
            .call(METHOD, json!([hash]))
            .await
            .map_err(|error| Self::transport_error(METHOD, &error))?;
        if value.is_null() {
            return Ok(None);
        }
        serde_json::from_value(value)
            .map(Some)
            .map_err(|error| BundlerError::Transport {
                method: METHOD,
                message: error.to_string(),
            })
    }
}

/// Why a Kernel permission grant or revoke failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KernelError {
    /// The spec was refused before anything went on chain: an empty
    /// scope, a backwards window, or a chain-0 grant.
    #[error("the grant spec was refused: {0}")]
    SpecInvalid(#[from] crate::grant::SpecError),
    /// The spec's scope is not an EVM Kernel grant, so this port has
    /// nothing to install.
    #[error("the grant scope is not an EVM Kernel grant")]
    ScopeMismatch,
    /// The signature did not match the credential the spec names: a
    /// passkey must sign with a WebAuthn assertion, an EIP-7702 EOA with
    /// its signed authorization.
    #[error("the owner signature does not match the grant's credential")]
    SignatureMismatch,
    /// The bundler refused or could not be reached.
    #[error("the bundler call failed: {0}")]
    Bundler(#[from] BundlerError),
    /// The permission was not found for the revoke.
    #[error("no such permission is installed: {0}")]
    UnknownPermission(String),
}

/// The Kernel permission port: the ERC-7579 permission validator on a
/// smart account. `grant` is the `toPermissionValidator` flow — install
/// the permission for the spec's session key with the spec's policies and
/// caps, and keep the serialized permission account
/// (`serializePermissionAccount`) it returns. `revoke` is
/// `uninstallPlugin`, signed by the owner.
#[async_trait::async_trait]
pub trait KernelPermissions: Send + Sync {
    /// Installs the permission for `spec` on the account, returning the
    /// [`OnChainBinding::KernelPermission`] to keep in the grant record —
    /// permission id and serialized permission account both.
    ///
    /// # Errors
    /// [`KernelError::SpecInvalid`] for a spec the crate refuses,
    /// [`KernelError::SignatureMismatch`] when the signature does not
    /// match the credential, [`KernelError::Bundler`] when the install
    /// operation fails.
    async fn grant(
        &self,
        spec: &GrantSpec,
        owner_signature: &OwnerSignature,
    ) -> Result<OnChainBinding, KernelError>;

    /// Builds and sends the `uninstallPlugin` operation for `binding`,
    /// signed by the owner. On-chain, this is the only way a grant ends
    /// without expiring — and it is the owner's signature, never the
    /// server's.
    ///
    /// # Errors
    /// [`KernelError::UnknownPermission`] when nothing is installed under
    /// that binding, [`KernelError::Bundler`] when the operation fails.
    async fn revoke(
        &self,
        binding: &OnChainBinding,
        owner_signature: &OwnerSignature,
    ) -> Result<UserOpHash, KernelError>;
}
