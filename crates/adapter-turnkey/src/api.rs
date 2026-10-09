//! The Turnkey API surface this crate speaks: JSON POSTs to
//! `https://api.turnkey.com/public/v1/submit/<activity>` with an
//! `X-Stamp` header, answered by an activity whose status is the
//! verdict. One [`TurnkeySigner`] serves one venture: the parent
//! organization id, and the Secrets-port name of the P-256 API key the
//! delegated access user stamps with — the same key pair registered as
//! our backend user's key on the parent organization.

use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Request, StatusCode};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use cratefield_core::{Clock, HttpClient, HttpError};
use cratefield_secrets::{Actor, SecretStore};
use cratefield_signer::SignerError;

use crate::policy::{AllowRule, da_consensus, validate_turnkey_id};

/// Turnkey's API root. `with_base` overrides it for a fake in tests.
const API_BASE: &str = "https://api.turnkey.com";

/// The activity statuses that mean "a policy or a quorum said no":
/// an explicit rejection, and a consensus that never formed because no
/// allow policy covered the request. Both are the port's `Denied`.
const DENIED_STATUSES: [&str; 2] = [
    "ACTIVITY_STATUS_REJECTED",
    "ACTIVITY_STATUS_CONSENSUS_NEEDED",
];

/// The end user's passkey, as the browser handed it back — the root
/// user's WebAuthn authenticator at sub-organization creation.
#[derive(Debug, Clone)]
pub struct PasskeyAttestation {
    /// Human-readable authenticator name.
    pub authenticator_name: String,
    /// The challenge, base64url, exactly as presented to the client.
    pub challenge: String,
    /// The credential id, CBOR-encoded then base64url.
    pub credential_id: String,
    /// The base64url client data JSON.
    pub client_data_json: String,
    /// The base64url attestation object.
    pub attestation_object: String,
    /// `AUTHENTICATOR_TRANSPORT_*` values, e.g. `HYBRID`.
    pub transports: Vec<String>,
}

/// One end user's sub-organization setup: a name, the passkey their
/// wallet is rooted in, and the allow rules the delegated access user
/// is scoped to.
#[derive(Debug, Clone)]
pub struct SubOrgSetup {
    /// The sub-organization's name, e.g. `acme:user-42`.
    pub name: String,
    /// The end user's name.
    pub end_user_name: String,
    /// The end user's email, when there is one.
    pub end_user_email: Option<String>,
    /// The passkey that becomes the root user's authenticator.
    pub authenticator: PasskeyAttestation,
    /// One `EFFECT_ALLOW` policy per rule, all scoped to the delegated
    /// access user.
    pub rules: Vec<AllowRule>,
}

/// What a successful setup hands back: everything [`crate::signer::key_ref`]
/// needs, plus the ids later administration calls go by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubOrganization {
    /// The sub-organization id.
    pub id: String,
    /// The end user's id — the root quorum's sole member once setup is
    /// done.
    pub end_user_id: String,
    /// The delegated access user's id — the consensus every policy this
    /// crate writes is scoped to.
    pub da_user_id: String,
    /// The wallet's id.
    pub wallet_id: String,
    /// The wallet's EVM account address (`0x`, lowercase), from the
    /// `m/44'/60'/0'/0/0` account.
    pub evm_address: Option<String>,
    /// The wallet's Solana account pubkey (base58), from the
    /// `m/44'/501'/0'/0'` account.
    pub solana_address: Option<String>,
}

/// One user of a sub-organization, as `list_users` reports it: the id,
/// and the public keys of any API keys registered on it — the shape
/// user identification goes by.
struct ListedUser {
    id: String,
    api_key_public_keys: Vec<String>,
}

/// The Turnkey provider for the [`KeySigner`](cratefield_signer::KeySigner)
/// port: setup, policies, kill switches, and signing by key reference.
///
/// No `Debug` derive: the fields name nothing secret (the API key is
/// referenced by its Secrets-port name), but a derived `Debug` would
/// print whatever is added later.
pub struct TurnkeySigner {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    /// The parent organization the backend's own API key belongs to;
    /// sub-organization creation is submitted here, everything else to
    /// the sub-organization itself.
    organization_id: String,
    /// The Secrets store holding the P-256 API key scalar.
    secrets: Arc<SecretStore>,
    /// Who every secrets access is attributed to.
    actor: Actor,
    /// The store name the API key scalar lives under.
    api_key_secret: String,
    /// `None` posts to [`API_BASE`]; a value overrides it for tests.
    base: Option<String>,
}

impl TurnkeySigner {
    /// A signer for `organization_id`, stamping with the P-256 scalar
    /// sealed in the Secrets store at `api_key_secret`, attributed to
    /// `actor`. Holds no credential itself — which key, and whose
    /// store, is the deployment's to say.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        organization_id: impl Into<String>,
        secrets: Arc<SecretStore>,
        actor: Actor,
        api_key_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            clock,
            organization_id: organization_id.into(),
            secrets,
            actor,
            api_key_secret: api_key_secret.into(),
            base: None,
        }
    }

    /// Overrides the URL every request is posted to — a fake in tests.
    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// The API key's compressed public key, hex — the value registered
    /// on the delegated access user at setup, and what an operator
    /// registers on the parent organization for this same key pair.
    ///
    /// # Errors
    ///
    /// [`SignerError::UnknownKey`] when the secret is not in the store,
    /// [`SignerError::Provider`] when it does not unseal to a scalar.
    pub async fn da_public_key(&self) -> Result<String, SignerError> {
        Ok(crate::stamp::compressed_public_key_hex(
            &self.load_stamp_key().await?,
        ))
    }

    /// Runs the whole setup flow against Turnkey, in order: create the
    /// sub-organization (end user's passkey + the delegated access
    /// user, both root, threshold 1, wallet with EVM and Solana
    /// accounts), read its users back and identify them — delegated
    /// access by this crate's API key, the end user as the other of
    /// exactly two — then one `EFFECT_ALLOW` policy per rule scoped to
    /// the delegated user, then `ACTIVITY_TYPE_UPDATE_ROOT_QUORUM` with
    /// the end user alone. Afterwards the backend can sign what the
    /// policies allow and nothing else — and cannot change the
    /// policies.
    ///
    /// A failure between the policy and quorum steps leaves the
    /// delegated user root: retry setup rather than abandon it, and
    /// see `set_kill_switch` for freezing a half-set-up sub-organization.
    ///
    /// # Errors
    ///
    /// [`SignerError`] — the first activity that is refused, rejected
    /// or fails stops the flow, as does a user listing that does not
    /// identify exactly one delegated access user.
    pub async fn create_sub_organization(
        &self,
        setup: &SubOrgSetup,
    ) -> Result<SubOrganization, SignerError> {
        let da_public_key = self.da_public_key().await?;
        let activity = self
            .submit(
                "create_sub_organization",
                "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V7",
                &self.organization_id,
                create_sub_organization_parameters(setup, &da_public_key),
            )
            .await?;
        let result = &activity["createSubOrganizationResult"];
        let id = turnkey_id(result["subOrganizationId"].as_str(), "subOrganizationId")?;
        // Who is who is not an ordering question: `rootUserIds` rides
        // in the order the users were sent, so it identifies nothing.
        // The users are read back (`POST /public/v1/query/list_users`)
        // and the delegated access user is whichever of them carries
        // this crate's API key, the end user the other of exactly two.
        // Anything ambiguous fails loudly here, before a policy or the
        // quorum hand-over can act on a guess.
        let listed = self.list_users(&id).await?;
        if listed.len() != 2 {
            return Err(SignerError::Provider(format!(
                "the new sub-organization holds {} users, not the two that were created; refusing \
                 to guess which is which",
                listed.len()
            )));
        }
        let carriers: Vec<&str> = listed
            .iter()
            .filter(|user| {
                user.api_key_public_keys
                    .iter()
                    .any(|key| key == &da_public_key)
            })
            .map(|user| user.id.as_str())
            .collect();
        if carriers.len() != 1 {
            return Err(SignerError::Provider(format!(
                "exactly one user of the new sub-organization must carry the delegated access \
                 API key, found {}; refusing to guess which is which",
                carriers.len()
            )));
        }
        let da_user_id = carriers[0].to_owned();
        let end_user_id = listed
            .iter()
            .map(|user| user.id.as_str())
            .find(|user_id| *user_id != da_user_id)
            .ok_or_else(|| {
                SignerError::Provider(
                    "the new sub-organization has no second user to be the end user".to_owned(),
                )
            })?
            .to_owned();
        let wallet = &result["wallet"];
        let wallet_id = wallet["walletId"]
            .as_str()
            .ok_or_else(|| {
                SignerError::Provider("the sub-organization result has no walletId".to_owned())
            })?
            .to_owned();
        // Addresses come back in account order: EVM, then Solana.
        let addresses: Vec<&str> = wallet["addresses"]
            .as_array()
            .map(|list| list.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let sub_org = SubOrganization {
            id,
            end_user_id,
            da_user_id,
            wallet_id,
            evm_address: addresses.first().map(|address| (*address).to_owned()),
            solana_address: addresses.get(1).map(|address| (*address).to_owned()),
        };

        for (at, rule) in setup.rules.iter().enumerate() {
            self.create_policy(
                &sub_org.id,
                &format!("cratefield-da-allow-{at}"),
                "EFFECT_ALLOW",
                &sub_org.da_user_id,
                Some(&rule.condition()),
                "cratefield: allow the delegated access user one rule (issue #761)",
            )
            .await?;
        }

        self.update_root_quorum(&sub_org.id, 1, std::slice::from_ref(&sub_org.end_user_id))
            .await?;
        Ok(sub_org)
    }

    /// Creates one policy on `sub_organization_id`. `effect` is
    /// `EFFECT_ALLOW` or `EFFECT_DENY`; the consensus is always the
    /// delegated access user — these policies decide the backend's
    /// requests and nobody else's. Returns the new policy's id.
    ///
    /// # Errors
    ///
    /// [`SignerError`] — a refused activity, or an id that is not a
    /// UUID.
    pub async fn create_policy(
        &self,
        sub_organization_id: &str,
        name: &str,
        effect: &str,
        da_user_id: &str,
        condition: Option<&str>,
        notes: &str,
    ) -> Result<String, SignerError> {
        let parameters = json!({
            "policyName": name,
            "effect": effect,
            "consensus": da_consensus(da_user_id)?,
            "condition": condition,
            "notes": notes,
        });
        let activity = self
            .submit(
                "create_policy",
                "ACTIVITY_TYPE_CREATE_POLICY_V3",
                sub_organization_id,
                parameters,
            )
            .await?;
        turnkey_id(
            activity["createPolicyResult"]["policyId"].as_str(),
            "policyId",
        )
    }

    /// The kill switch: an `EFFECT_DENY` policy scoped to the delegated
    /// access user whose condition is `true`. While it exists nothing
    /// the backend signs is approved — allow policies say what *may*
    /// pass, a deny policy says nothing does. Returns the policy id to
    /// hand to [`TurnkeySigner::clear_kill_switch`].
    ///
    /// # Errors
    ///
    /// [`SignerError`] — see [`TurnkeySigner::create_policy`].
    pub async fn set_kill_switch(
        &self,
        sub_organization_id: &str,
        da_user_id: &str,
    ) -> Result<String, SignerError> {
        self.create_policy(
            sub_organization_id,
            "cratefield-da-kill-switch",
            "EFFECT_DENY",
            da_user_id,
            Some("true"),
            "cratefield: kill switch — deny the delegated access user everything (issue #761)",
        )
        .await
    }

    /// Lifts the kill switch by deleting the policy `policy_id` names.
    ///
    /// # Errors
    ///
    /// [`SignerError`] — a refused activity.
    pub async fn clear_kill_switch(
        &self,
        sub_organization_id: &str,
        policy_id: &str,
    ) -> Result<(), SignerError> {
        self.submit(
            "delete_policy",
            "ACTIVITY_TYPE_DELETE_POLICY",
            sub_organization_id,
            json!({ "policyId": policy_id }),
        )
        .await?;
        Ok(())
    }

    /// Moves the root quorum to `threshold` approvals from `user_ids` —
    /// the setup flow's last step, which takes the backend out of it.
    ///
    /// # Errors
    ///
    /// [`SignerError`] — a refused activity.
    pub async fn update_root_quorum(
        &self,
        sub_organization_id: &str,
        threshold: u32,
        user_ids: &[String],
    ) -> Result<(), SignerError> {
        for id in user_ids {
            validate_turnkey_id(id)?;
        }
        self.submit(
            "update_root_quorum",
            "ACTIVITY_TYPE_UPDATE_ROOT_QUORUM",
            sub_organization_id,
            json!({ "threshold": threshold, "userIds": user_ids }),
        )
        .await?;
        Ok(())
    }

    /// Signs an unsigned transaction: `ACTIVITY_TYPE_SIGN_TRANSACTION_V2`,
    /// the one activity Turnkey's policy engine parses `eth.tx.*`
    /// conditions against. Returns the signed transaction hex.
    ///
    /// # Errors
    ///
    /// [`SignerError`] — denied by policy, or a failed activity.
    pub(crate) async fn sign_transaction(
        &self,
        sub_organization_id: &str,
        sign_with: &str,
        unsigned_transaction_hex: &str,
        transaction_type: &str,
    ) -> Result<String, SignerError> {
        let activity = self
            .submit(
                "sign_transaction",
                "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
                sub_organization_id,
                json!({
                    "signWith": sign_with,
                    "unsignedTransaction": unsigned_transaction_hex,
                    "type": transaction_type,
                }),
            )
            .await?;
        activity["signTransactionResult"]["signedTransaction"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| {
                SignerError::Provider("the sign result carries no signedTransaction".to_owned())
            })
    }

    /// Signs a payload: `ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2`. Note the
    /// policy engine does **not** parse raw payloads — `eth.tx.*` rules
    /// only bind on [`TurnkeySigner::sign_transaction`]. Returns
    /// `(r, s, v)` as hex strings.
    ///
    /// # Errors
    ///
    /// [`SignerError`] — denied by policy, or a failed activity.
    pub(crate) async fn sign_raw_payload(
        &self,
        sub_organization_id: &str,
        sign_with: &str,
        payload_hex: &str,
        hash_function: &str,
    ) -> Result<(String, String, String), SignerError> {
        let activity = self
            .submit(
                "sign_raw_payload",
                "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                sub_organization_id,
                json!({
                    "signWith": sign_with,
                    "payload": payload_hex,
                    "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
                    "hashFunction": hash_function,
                }),
            )
            .await?;
        let result = &activity["signRawPayloadResult"];
        let r = result["r"].as_str().ok_or_else(missing_signature)?;
        let s = result["s"].as_str().ok_or_else(missing_signature)?;
        let v = result["v"].as_str().ok_or_else(missing_signature)?;
        Ok((r.to_owned(), s.to_owned(), v.to_owned()))
    }

    /// Posts one activity and returns its `result` object once the
    /// activity has completed — every status short of that is an error,
    /// mapped in [`activity_result`].
    async fn submit(
        &self,
        path: &str,
        activity_type: &str,
        organization_id: &str,
        parameters: Value,
    ) -> Result<Value, SignerError> {
        if organization_id.is_empty() {
            return Err(SignerError::Invalid(
                "a Turnkey organization id is required".to_owned(),
            ));
        }
        // timestampMs rides as a string, and the clock is a port: a
        // deployment's idea of "now" is its runtime's, not this crate's.
        let timestamp_ms = self.clock.now().unix_timestamp_nanos() / 1_000_000;
        let body = serde_json::to_vec(&json!({
            "type": activity_type,
            "timestampMs": timestamp_ms.to_string(),
            "organizationId": organization_id,
            "parameters": parameters,
        }))
        .map_err(|err| SignerError::Provider(format!("the request could not be built: {err}")))?;
        let answer = self.post("submit", path, body).await?;
        let activity = &answer["activity"];
        activity_result(activity_type, activity)
    }

    /// The users of a sub-organization, from Turnkey's read endpoint
    /// `POST /public/v1/query/list_users` — the query twin of the
    /// submit posts: same stamp, but no activity envelope, the answer
    /// is the JSON as it comes.
    async fn list_users(&self, sub_organization_id: &str) -> Result<Vec<ListedUser>, SignerError> {
        let body = serde_json::to_vec(&json!({ "organizationId": sub_organization_id })).map_err(
            |err| SignerError::Provider(format!("the request could not be built: {err}")),
        )?;
        let answer = self.post("query", "list_users", body).await?;
        let users = answer["users"].as_array().ok_or_else(|| {
            SignerError::Provider("the list_users answer carries no users".to_owned())
        })?;
        let mut listed = Vec::with_capacity(users.len());
        for user in users {
            listed.push(ListedUser {
                id: turnkey_id(user["userId"].as_str(), "userId")?,
                api_key_public_keys: user["apiKeys"]
                    .as_array()
                    .map(|keys| {
                        keys.iter()
                            .filter_map(|key| key["credential"]["publicKey"].as_str())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
        Ok(listed)
    }

    /// Posts an already-built body to `public/v1/{kind}/{name}` —
    /// `submit/…` activities and `query/…` reads are the same wire:
    /// stamped, JSON in, JSON out.
    async fn post(&self, kind: &str, name: &str, body: Vec<u8>) -> Result<Value, SignerError> {
        let key = self.load_stamp_key().await?;
        let stamp = crate::stamp::stamp_with_key(&body, &key);
        drop(key);
        let header = HeaderValue::from_str(&stamp)
            .map_err(|_| SignerError::Provider("the stamp is not a legal header".to_owned()))?;
        let uri = format!(
            "{}/public/v1/{kind}/{name}",
            self.base.as_deref().unwrap_or(API_BASE)
        );
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header("X-Stamp", header)
            .header(CONTENT_TYPE, "application/json")
            .body(Bytes::from(body))
            .map_err(|_| SignerError::Provider("the request could not be built".to_owned()))?;

        let response = self.http.send(request).await.map_err(|err: HttpError| {
            SignerError::Provider(format!("turnkey is unreachable: {err}"))
        })?;
        let status = response.status();
        let text = String::from_utf8_lossy(response.body()).to_string();
        if !status.is_success() {
            return Err(SignerError::Provider(format!(
                "turnkey answered {}: {text}",
                StatusCode::as_u16(&status)
            )));
        }
        serde_json::from_str(&text).map_err(|err| {
            SignerError::Provider(format!("turnkey answered unparsable JSON: {err}"))
        })
    }

    /// Unseals the API key scalar. The bytes exist in the clear exactly
    /// here, in a `Zeroizing` buffer that drops with the call — the
    /// same shape `SecretsSigner::unseal` keeps its keys in.
    async fn load_stamp_key(&self) -> Result<p256::ecdsa::SigningKey, SignerError> {
        let sealed = self
            .secrets
            .get(&self.api_key_secret, &self.actor)
            .await
            .map_err(|err| SignerError::Provider(format!("the secrets store refused: {err}")))?
            .ok_or_else(|| SignerError::UnknownKey {
                key_ref: self.api_key_secret.clone(),
            })?;
        let scalar = Zeroizing::new(<[u8; 32]>::try_from(sealed.expose()).map_err(|_| {
            SignerError::Provider(format!(
                "the Turnkey API key behind `{}` is {} bytes, not the 32-byte P-256 scalar",
                self.api_key_secret,
                sealed.expose().len()
            ))
        })?);
        crate::stamp::signing_key(scalar.as_slice())
    }
}

/// Reads one completed activity's `result` object, mapping every other
/// status onto the port: policy rejections and unformed consensus are
/// [`SignerError::Denied`], Turnkey-side failures and anything
/// unexpected are [`SignerError::Provider`].
fn activity_result(activity_type: &str, activity: &Value) -> Result<Value, SignerError> {
    let status = activity["status"].as_str().unwrap_or("missing");
    match status {
        "ACTIVITY_STATUS_COMPLETED" => Ok(activity["result"].clone()),
        status if DENIED_STATUSES.contains(&status) => Err(SignerError::Denied {
            reason: format!(
                "turnkey refused the {activity_type}: the activity is {status} — a policy denied \
                 it, or the delegated user's consensus was not enough"
            ),
        }),
        other => Err(SignerError::Provider(format!(
            "the turnkey {activity_type} did not complete: status {other}"
        ))),
    }
}

/// The signature components the answer must carry.
fn missing_signature() -> SignerError {
    SignerError::Provider("the sign result carries no (r, s, v)".to_owned())
}

/// Reads a Turnkey object id out of an answer, refusing one that is not
/// a UUID before it can travel anywhere.
fn turnkey_id(value: Option<&str>, field: &str) -> Result<String, SignerError> {
    let id = value
        .ok_or_else(|| SignerError::Provider(format!("the activity result has no {field}")))?;
    crate::policy::validate_turnkey_id(id)
}

/// The `CREATE_SUB_ORGANIZATION_V7` parameters: the end user (passkey
/// attestation, nothing else) and the delegated access user (this
/// crate's API key, no authenticator) as the two root users at
/// threshold 1, and the wallet with one EVM and one Solana account.
fn create_sub_organization_parameters(setup: &SubOrgSetup, da_public_key: &str) -> Value {
    json!({
        "subOrganizationName": setup.name,
        "rootUsers": [
            {
                "userName": setup.end_user_name,
                "userEmail": setup.end_user_email,
                "apiKeys": [],
                "authenticators": [{
                    "authenticatorName": setup.authenticator.authenticator_name,
                    "challenge": setup.authenticator.challenge,
                    "attestation": {
                        "credentialId": setup.authenticator.credential_id,
                        "clientDataJson": setup.authenticator.client_data_json,
                        "attestationObject": setup.authenticator.attestation_object,
                        "transports": setup.authenticator.transports,
                    },
                }],
                "oauthProviders": [],
            },
            {
                // The delegated access user: API key only, no
                // authenticator — nothing human can log in as it.
                "userName": "cratefield-delegated",
                "userEmail": null,
                "apiKeys": [{
                    "apiKeyName": "cratefield-da",
                    "publicKey": da_public_key,
                    "curveType": "API_KEY_CURVE_P256",
                }],
                "authenticators": [],
                "oauthProviders": [],
            },
        ],
        "rootQuorumThreshold": 1,
        "wallet": {
            "walletName": "cratefield",
            "accounts": [
                {
                    "curve": "CURVE_SECP256K1",
                    "pathFormat": "PATH_FORMAT_BIP32",
                    "path": "m/44'/60'/0'/0/0",
                    "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
                },
                {
                    "curve": "CURVE_ED25519",
                    "pathFormat": "PATH_FORMAT_BIP32",
                    "path": "m/44'/501'/0'/0'",
                    "addressFormat": "ADDRESS_FORMAT_SOLANA",
                },
            ],
        },
    })
}
