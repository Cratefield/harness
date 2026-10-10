//! The `GuardedSigner`: the composition a venture uses. It wraps any
//! [`KeySigner`] so that no signature is possible except through the
//! guardrails and the audit chain, in that order — and the provider is
//! unreachable from here on any other path.
//!
//! The composition is deliberately *not* itself a `KeySigner`: its
//! `sign` takes the subject, which the trait's method does not, so a
//! guarded signer cannot be smuggled into a code path that expects an
//! unguarded one. The trait is the unguarded seam; this type is the
//! guarded one, and the compiler keeps them apart.
//!
//! ```compile_fail
//! use cratefield_signer::{FakeSigner, GuardedSigner, MemorySignAudit, StaticGuardrails};
//! let signer: GuardedSigner<FakeSigner, StaticGuardrails, MemorySignAudit> =
//!     GuardedSigner::new(FakeSigner::new(), StaticGuardrails::new(), MemorySignAudit::new());
//! // There is no accessor back to the provider, so this line does not
//! // compile: `sign` here is the only signing path.
//! let _provider: &FakeSigner = signer.signer();
//! ```

use crate::audit::{PolicyDecisionRecord, SignAudit, SignAuditRecord, SignOutcome, now};
use crate::guardrails::{Guardrails, PolicyDecision, SignContext};
use crate::keys::{KeyInfo, KeyRef, Scheme, Signature, Subject};
use crate::payload::{Intent, Payload};
use crate::port::KeySigner;
use crate::port::SignerError;

/// A [`KeySigner`] behind the guardrails and the audit chain. `sign`
/// decodes the payload's intent, asks the guardrails, records the
/// decision, calls the provider only on **allow**, and records the
/// outcome; every other path — a decode failure, a deny, a guardrail
/// that cannot evaluate, an audit trail that refuses to record — ends
/// with an error and a provider that was never called.
///
/// The audit trail fails closed on both ends: a decision that cannot be
/// recorded stops the provider call, and an outcome that cannot be
/// recorded means the signature is not returned even though it was
/// produced.
///
/// Key creation passes through unchanged: minting a session key signs
/// nothing. The guardrails govern signatures.
pub struct GuardedSigner<S, G, A> {
    signer: S,
    guardrails: G,
    audit: A,
}

impl<S, G, A> GuardedSigner<S, G, A> {
    /// Wraps a provider with guardrails and an audit sink.
    #[must_use]
    pub fn new(signer: S, guardrails: G, audit: A) -> Self {
        Self {
            signer,
            guardrails,
            audit,
        }
    }

    // No `signer()` accessor: the provider is reachable only through the
    // guarded `sign` below and the two key-management methods, so a
    // caller cannot step around the guardrails and the audit chain. A
    // test that needs its own handle keeps one before wrapping.
}

impl<S, G, A> GuardedSigner<S, G, A>
where
    S: KeySigner,
    G: Guardrails,
    A: SignAudit,
{
    /// Mints a key through the provider: a fresh session key for
    /// `subject` on `scheme`.
    ///
    /// # Errors
    ///
    /// As the provider's `create_key`.
    pub async fn create_key(
        &self,
        subject: &Subject,
        scheme: Scheme,
        label: &str,
    ) -> Result<KeyInfo, SignerError> {
        self.signer.create_key(subject, scheme, label).await
    }

    /// The public description of `key_ref`, through the provider.
    ///
    /// # Errors
    ///
    /// As the provider's `key`.
    pub async fn key(&self, key_ref: &KeyRef) -> Result<KeyInfo, SignerError> {
        self.signer.key(key_ref).await
    }

    /// The whole point: `subject` asks `key_ref` to sign `payload`, and
    /// this decides, records, and only then signs.
    ///
    /// # Errors
    ///
    /// [`SignerError::Payload`] when the payload does not decode or
    /// hash, [`SignerError::Denied`] when the guardrails say no,
    /// [`SignerError::Audit`] when any audit record fails (the signature
    /// is never returned in that case), or whatever the provider
    /// raises, recorded first.
    pub async fn sign(
        &self,
        subject: &Subject,
        key_ref: &KeyRef,
        payload: &Payload,
    ) -> Result<Signature, SignerError> {
        // Decode and hash first: an undecodable payload never reaches
        // the provider, and is denied on the record with an all-zero
        // hash — the attempt happened, and the audit chain is where it
        // shows.
        let (intent, payload_hash) = match payload
            .intent()
            .and_then(|intent| Ok((intent, payload.payload_hash()?)))
        {
            Ok(pair) => pair,
            Err(err) => {
                self.write(
                    subject,
                    key_ref,
                    [0_u8; 32],
                    None,
                    PolicyDecisionRecord::Deny {
                        reason: format!("the payload did not decode: {err}"),
                    },
                    SignOutcome::NotAttempted,
                )
                .await?;
                return Err(err);
            }
        };

        let decision = match self
            .guardrails
            .check(&SignContext {
                subject: subject.clone(),
                key_ref: key_ref.clone(),
                payload_hash,
                intent: intent.clone(),
            })
            .await
        {
            Ok(decision) => decision,
            Err(err) => {
                // A guardrail that cannot evaluate is not an allow.
                self.write(
                    subject,
                    key_ref,
                    payload_hash,
                    Some(intent),
                    PolicyDecisionRecord::Deny {
                        reason: format!("the guardrails failed: {err}"),
                    },
                    SignOutcome::NotAttempted,
                )
                .await?;
                return Err(err);
            }
        };

        if let PolicyDecision::Deny { reason } = &decision {
            // Denied: one record, nothing further, and the caller sees
            // the reason as the error.
            self.write(
                subject,
                key_ref,
                payload_hash,
                Some(intent),
                PolicyDecisionRecord::from(&decision),
                SignOutcome::NotAttempted,
            )
            .await?;
            return Err(SignerError::Denied {
                reason: reason.clone(),
            });
        }

        // Allowed: the decision is on the record *before* the provider
        // runs, so a crash leaves an allowed-but-not-attempted entry
        // rather than a signature nobody decided on.
        self.write(
            subject,
            key_ref,
            payload_hash,
            Some(intent.clone()),
            PolicyDecisionRecord::Allow,
            SignOutcome::NotAttempted,
        )
        .await?;

        match self.signer.sign(key_ref, payload).await {
            Ok(signature) => {
                self.write(
                    subject,
                    key_ref,
                    payload_hash,
                    Some(intent),
                    PolicyDecisionRecord::Allow,
                    SignOutcome::Signed,
                )
                .await?;
                Ok(signature)
            }
            Err(err) => {
                let error = err.to_string();
                self.write(
                    subject,
                    key_ref,
                    payload_hash,
                    Some(intent),
                    PolicyDecisionRecord::Allow,
                    SignOutcome::ProviderError { error },
                )
                .await?;
                Err(err)
            }
        }
    }

    /// One audit record, or the error that fails the attempt closed.
    async fn write(
        &self,
        subject: &Subject,
        key_ref: &KeyRef,
        payload_hash: [u8; 32],
        intent: Option<Intent>,
        decision: PolicyDecisionRecord,
        outcome: SignOutcome,
    ) -> Result<(), SignerError> {
        self.audit
            .record(&SignAuditRecord {
                subject: subject.clone(),
                key_ref: key_ref.clone(),
                payload_hash: format!("0x{}", hex::encode(payload_hash)),
                intent,
                decision,
                outcome,
                at: now(),
            })
            .await
            .map_err(|err| {
                SignerError::Audit(format!(
                    "the audit trail refused the record, so the signature did not happen: {err}"
                ))
            })
    }
}
