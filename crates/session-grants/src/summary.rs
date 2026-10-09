//! The summary the owner reads *before* signing: a pure function from the
//! grant spec to a display model, so the UI that asks for the signature
//! and the server that composes the spec cannot drift on what is being
//! agreed to.

use std::fmt::Write as _;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::grant::{
    CallPolicy, EvmGrant, GrantScope, GrantSpec, NativeLimit, ProgramScope, RecurringLimit,
    SpendPeriod, SpendingLimit, SquadsGrant,
};

/// The display model for one grant. Everything the owner is agreeing to,
/// and nothing they are not: each named contract or program, its caps,
/// the rate limit and the expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantSummary {
    /// The grant id the summary describes.
    pub grant_id: String,
    /// "EVM · chain 8453", "Solana · mainnet": the chain, as the owner
    /// reads it.
    pub chain: String,
    /// The account or wallet the grant acts through.
    pub actor: String,
    /// How the owner signs: which credential, that its key stays in the
    /// authenticator (for a passkey).
    pub signed_by: String,
    /// Every contract, program or vault the grant names, with its caps.
    pub entries: Vec<SummaryEntry>,
    /// The overall caps that span entries.
    pub caps: Vec<String>,
    /// The rate limit, when the spec sets one.
    pub rate_limit: Option<String>,
    /// The first instant the server may act, RFC 3339.
    pub valid_after: String,
    /// The last instant the server may act, RFC 3339. The expiry is the
    /// one line every summary carries.
    pub valid_until: String,
}

/// One named contract/program and what the grant may do to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SummaryEntry {
    /// "contract", "program", "wallet role" or "treasury vault": the kind
    /// of thing being granted to.
    pub kind: &'static str,
    /// The address or program id, as the owner can look it up on an
    /// explorer.
    pub name: String,
    /// What may be done there: selectors, or the spending limit's shape.
    pub actions: Vec<String>,
    /// The caps attached to this entry, human-readable.
    pub caps: Vec<String>,
}

/// Renders the summary for the owner to read before signing.
#[must_use]
pub fn summarize(spec: &GrantSpec) -> GrantSummary {
    let chain = match &spec.scope {
        GrantScope::EvmKernel(grant) => format!("EVM · chain {}", grant.chain_id),
        GrantScope::SolanaSwig(grant) => format!("Solana · {}", grant.cluster),
        GrantScope::SolanaSquads(grant) => format!("Solana · {}", grant.cluster),
    };
    let (actor, signed_by) = match &spec.scope {
        GrantScope::EvmKernel(grant) => (grant.account.to_string(), summarize_credential(spec)),
        GrantScope::SolanaSwig(grant) => (
            format!("{} (role session {})", grant.swig, grant.session_key),
            summarize_credential(spec),
        ),
        GrantScope::SolanaSquads(grant) => (
            format!("{} vault #{}", grant.multisig, grant.vault_index),
            summarize_credential(spec),
        ),
    };
    let (entries, caps) = summarize_scope(spec);

    GrantSummary {
        grant_id: spec.id.clone(),
        chain,
        actor,
        signed_by,
        entries,
        caps,
        rate_limit: spec.rate_limit.map(|limit| {
            format!(
                "at most {} calls per {}",
                limit.max_calls,
                secs(limit.period_secs)
            )
        }),
        valid_after: rfc3339(spec.window.valid_after),
        valid_until: rfc3339(spec.window.valid_until),
    }
}

/// The credential line: for a passkey, says the key cannot be exported.
fn summarize_credential(spec: &GrantSpec) -> String {
    match &spec.credential {
        crate::OwnerCredential::Passkey { credential_id } => {
            format!("your passkey {credential_id} — the key never leaves your authenticator")
        }
        crate::OwnerCredential::Eip7702 { address } => {
            format!("your EOA {address} (EIP-7702 delegation on the named chain)")
        }
    }
}

/// The per-protocol entries and the spanning caps.
fn summarize_scope(spec: &GrantSpec) -> (Vec<SummaryEntry>, Vec<String>) {
    match &spec.scope {
        GrantScope::EvmKernel(grant) => {
            let entries = grant
                .calls
                .iter()
                .map(|call| summarize_call(grant, call))
                .collect();
            let mut caps = Vec::new();
            if let Some(limit) = &grant.value_limit {
                caps.push(format!("at most {} in total", eth(limit.recurring.amount)));
            }
            if let Some(limit) = &grant.token_limit {
                caps.push(format!(
                    "at most {} of token {} in total",
                    plain(limit.recurring.amount),
                    limit.token
                ));
            }
            (entries, caps)
        }
        GrantScope::SolanaSwig(grant) => {
            let entries = grant.programs.iter().map(summarize_program).collect();
            let mut caps = Vec::new();
            if let Some(limit) = &grant.sol_limit {
                caps.push(summarize_native_limit("SOL", limit));
            }
            for limit in &grant.token_limits {
                caps.push(format!(
                    "at most {} of mint {} per {} in total{}",
                    plain(limit.recurring.amount),
                    limit.token,
                    secs(limit.recurring.period_secs),
                    per_destination_suffix(limit.per_destination.as_ref(), plain)
                ));
            }
            (entries, caps)
        }
        GrantScope::SolanaSquads(grant) => {
            let entries = grant
                .limits
                .iter()
                .map(|limit| summarize_spending_limit(grant, limit))
                .collect();
            (entries, Vec::new())
        }
    }
}

fn summarize_call(grant: &EvmGrant, call: &CallPolicy) -> SummaryEntry {
    let mut actions = vec![format!("call {}", call.selector)];
    for arg in &call.args {
        actions.push(format!("argument {} must be {}", arg.index, arg.equals));
    }
    let mut caps = Vec::new();
    if let Some(cap) = call.value_cap {
        caps.push(format!("at most {} per call", eth(cap)));
    } else if grant.value_limit.is_none() {
        caps.push("no value may be sent".to_owned());
    }
    SummaryEntry {
        kind: "contract",
        name: call.target.to_string(),
        actions,
        caps,
    }
}

fn summarize_program(program: &ProgramScope) -> SummaryEntry {
    SummaryEntry {
        kind: "program",
        name: program.program.to_string(),
        actions: vec!["any instruction to this program".to_owned()],
        caps: Vec::new(),
    }
}

fn summarize_spending_limit(grant: &SquadsGrant, limit: &SpendingLimit) -> SummaryEntry {
    let amount = match &limit.mint {
        None => sol(limit.amount),
        Some(mint) => format!("{} of {mint}", plain(limit.amount)),
    };
    let actions = vec![format!(
        "spend up to {amount} per {} from the vault",
        spend_period(limit.period)
    )];
    let mut caps = Vec::new();
    if !limit.destinations.is_empty() {
        caps.push(format!("only to {} recipient(s)", limit.destinations.len()));
    }
    SummaryEntry {
        kind: "treasury vault",
        name: format!("{} vault #{}", grant.multisig, grant.vault_index),
        actions,
        caps,
    }
}

fn summarize_native_limit(unit: &str, limit: &NativeLimit) -> String {
    let render = |amount: u128| match unit {
        "SOL" => sol(amount),
        _ => plain(amount),
    };
    format!(
        "at most {} per {} in total{}",
        render(limit.recurring.amount),
        secs(limit.recurring.period_secs),
        per_destination_suffix(limit.per_destination.as_ref(), render)
    )
}

fn per_destination_suffix(
    limit: Option<&RecurringLimit>,
    render: impl Fn(u128) -> String,
) -> String {
    match limit {
        None => String::new(),
        Some(limit) => format!(
            ", and at most {} to any one destination per {}",
            render(limit.amount),
            secs(limit.period_secs)
        ),
    }
}

/// Formats a lamport amount as SOL, trailing zeros trimmed.
fn sol(lamports: u128) -> String {
    decimals(lamports, 9, "SOL")
}

/// Formats a wei amount as ETH, trailing zeros trimmed.
fn eth(wei: u128) -> String {
    decimals(wei, 18, "ETH")
}

/// Formats `amount` with `decimals` decimals, trailing zeros trimmed.
fn decimals(amount: u128, decimals: u32, unit: &str) -> String {
    let scale = 10u128.pow(decimals);
    let whole = amount / scale;
    let frac = amount % scale;
    if frac == 0 {
        return format!("{whole} {unit}");
    }
    let mut digits = format!(
        "{frac:0width$}",
        width = usize::try_from(decimals).unwrap_or(0)
    );
    while digits.ends_with('0') {
        digits.pop();
    }
    format!("{whole}.{digits} {unit}")
}

/// Formats an amount with no unit scaling (token units are app-defined).
fn plain(amount: u128) -> String {
    let text = amount.to_string();
    let mut grouped = String::new();
    for (at, ch) in text.chars().enumerate() {
        if at > 0 && (text.len() - at).is_multiple_of(3) {
            grouped.push('\'');
        }
        grouped.push(ch);
    }
    grouped
}

/// Formats a seconds count as a human period.
fn secs(secs: u64) -> String {
    match secs {
        3_600 => "hour".to_owned(),
        86_400 => "day".to_owned(),
        604_800 => "week".to_owned(),
        2_592_000 => "month".to_owned(),
        other => format!("{other} s"),
    }
}

fn spend_period(period: SpendPeriod) -> &'static str {
    match period {
        SpendPeriod::Once => "single spend",
        SpendPeriod::Daily => "day",
        SpendPeriod::Weekly => "week",
        SpendPeriod::Monthly => "month",
    }
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "invalid timestamp".to_owned())
}

impl GrantSummary {
    /// Renders the summary as plain text, one bullet per fact — the shape
    /// a consent screen, a log line or a terminal confirm prompt renders.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = String::new();
        let _ = writeln!(text, "Grant {} on {}", self.grant_id, self.chain);
        let _ = writeln!(text, "  acts through: {}", self.actor);
        let _ = writeln!(text, "  signed by: {}", self.signed_by);
        for entry in &self.entries {
            let _ = writeln!(
                text,
                "  {} {}: {}",
                entry.kind,
                entry.name,
                entry.actions.join("; ")
            );
            for cap in &entry.caps {
                let _ = writeln!(text, "    {cap}");
            }
        }
        for cap in &self.caps {
            let _ = writeln!(text, "  cap: {cap}");
        }
        if let Some(rate) = &self.rate_limit {
            let _ = writeln!(text, "  {rate}");
        }
        let _ = writeln!(
            text,
            "  valid from {} until {}",
            self.valid_after, self.valid_until
        );
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{ArgCondition, SquadsGrant, SwigGrant, ValidityWindow};
    use crate::types::{Address, OwnerCredential, Pubkey, Selector};

    #[test]
    fn eth_amounts_trim_trailing_zeros() {
        assert_eq!(eth(1_000_000_000_000_000_000), "1 ETH");
        assert_eq!(eth(1_500_000_000_000_000_000), "1.5 ETH");
        assert_eq!(eth(10_000_000_000), "0.00000001 ETH");
    }

    #[test]
    fn plain_amounts_group_digits() {
        assert_eq!(plain(1_000_000), "1'000'000");
        assert_eq!(plain(42), "42");
    }

    fn address(byte: u8) -> Address {
        let hex = format!("0x{byte:064}");
        Address::parse(&hex[..42]).expect("an address")
    }

    /// A made-up Solana key: 44 copies of `ch` — valid base58 by the
    /// crate's rules, unmistakably not a real account.
    fn made_up_key(ch: char) -> Pubkey {
        let key: String = std::iter::repeat_n(ch, 44).collect();
        Pubkey::parse(&key).expect("a made-up key")
    }

    #[test]
    fn window_and_rate_render_into_the_summary() {
        let at = time::Date::from_calendar_date(2026, time::Month::October, 9)
            .expect("a date")
            .midnight()
            .assume_utc();
        let spec = GrantSpec {
            id: "grant-1".into(),
            owner: "user-1".into(),
            credential: OwnerCredential::Passkey {
                credential_id: "cred-9".into(),
            },
            window: ValidityWindow {
                valid_after: at,
                valid_until: at + time::Duration::days(7),
            },
            rate_limit: Some(crate::grant::RateLimit {
                max_calls: 50,
                period_secs: 3_600,
            }),
            scope: GrantScope::EvmKernel(EvmGrant {
                chain_id: 8453,
                account: address(1),
                session_key: address(2),
                calls: vec![CallPolicy {
                    target: address(3),
                    selector: Selector::parse("0xa9059cbb").expect("a selector"),
                    args: vec![ArgCondition {
                        index: 0,
                        equals: "0x0000000000000000000000000000000000000004".into(),
                    }],
                    value_cap: Some(500_000_000_000_000_000),
                }],
                value_limit: Some(NativeLimit {
                    recurring: RecurringLimit {
                        amount: 1_000_000_000_000_000_000,
                        period_secs: 86_400,
                    },
                    per_destination: None,
                }),
                token_limit: None,
            }),
        };
        let summary = summarize(&spec);
        assert_eq!(summary.chain, "EVM · chain 8453");
        assert!(summary.signed_by.contains("passkey cred-9"));
        assert!(summary.signed_by.contains("never leaves"));
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(summary.entries[0].kind, "contract");
        assert!(summary.caps[0].contains("1 ETH in total"));
        assert_eq!(
            summary.rate_limit.as_deref(),
            Some("at most 50 calls per hour")
        );

        let text = summary.render();
        assert!(text.contains("0xa9059cbb"));
        assert!(text.contains("argument 0 must be 0x0000000000000000000000000000000000000004"));
        assert!(text.contains("0.5 ETH per call"));
        assert!(text.contains("until 2026-10-16"));
    }

    #[test]
    fn swig_summary_names_programs_and_per_destination_caps() {
        let swig = made_up_key('1');
        let program = made_up_key('3');
        let destination = made_up_key('2');
        let spec = GrantSpec {
            id: "grant-2".into(),
            owner: "user-1".into(),
            credential: OwnerCredential::Passkey {
                credential_id: "cred-5".into(),
            },
            window: ValidityWindow {
                valid_after: OffsetDateTime::UNIX_EPOCH,
                valid_until: OffsetDateTime::UNIX_EPOCH + time::Duration::days(30),
            },
            rate_limit: None,
            scope: GrantScope::SolanaSwig(SwigGrant {
                cluster: crate::grant::Cluster::Mainnet,
                swig: swig.clone(),
                role_id: None,
                session_key: program.clone(),
                session_ttl_secs: 86_400,
                programs: vec![ProgramScope {
                    program: program.clone(),
                }],
                sol_limit: Some(NativeLimit {
                    recurring: RecurringLimit {
                        amount: 2_000_000_000,
                        period_secs: 3_600,
                    },
                    per_destination: Some(RecurringLimit {
                        amount: 500_000_000,
                        period_secs: 3_600,
                    }),
                }),
                token_limits: Vec::new(),
            }),
        };
        let summary = summarize(&spec);
        assert!(summary.caps[0].contains("2 SOL per hour"));
        assert!(summary.caps[0].contains("at most 0.5 SOL to any one destination"));
        assert_eq!(summary.entries[0].kind, "program");
        assert_eq!(summary.entries[0].name, program.to_string());

        let text = summary.render();
        assert!(!text.contains(&destination.to_string()));
        assert!(text.contains(&format!("acts through: {swig}")));
    }

    #[test]
    fn squads_summary_names_the_vault_and_period() {
        let multisig = made_up_key('1');
        let mint = made_up_key('5');
        let destination = made_up_key('2');
        let spec = GrantSpec {
            id: "grant-3".into(),
            owner: "treasury".into(),
            credential: OwnerCredential::Passkey {
                credential_id: "cred-2".into(),
            },
            window: ValidityWindow {
                valid_after: OffsetDateTime::UNIX_EPOCH,
                valid_until: OffsetDateTime::UNIX_EPOCH + time::Duration::days(30),
            },
            rate_limit: None,
            scope: GrantScope::SolanaSquads(SquadsGrant {
                cluster: crate::grant::Cluster::Mainnet,
                multisig: multisig.clone(),
                vault_index: 2,
                limits: vec![SpendingLimit {
                    mint: Some(mint.clone()),
                    amount: 5_000_000_000,
                    period: SpendPeriod::Weekly,
                    destinations: vec![destination],
                }],
            }),
        };
        let text = summarize(&spec).render();
        assert!(text.contains("vault #2"));
        assert!(text.contains(&format!("5'000'000'000 of {mint}")));
        assert!(text.contains("per week"));
        assert!(text.contains("only to 1 recipient(s)"));
    }
}
