//! Money, charge amounts and the ledger entry (ADR 0025 decision 3, issue #594).
//!
//! [`Money`] itself lives in the `Payments` port; this module adds the
//! ISO 4217 exponent table, the [`major_to_minor`] converter, the
//! [`ChargeAmounts`] decomposition `RevenueCat`'s `MonetaryAmount` maps
//! onto, and the immutable [`LedgerEntry`] row a correction appends rather
//! than rewrites.

use thiserror::Error;
use time::OffsetDateTime;

use crate::billing::event::{Environment, Provider, Store};
use crate::ports::Money;

/// `i64::MIN` as an `f64`: exactly -2^63, the lowest scaled amount that
/// still fits in an `i64`.
const I64_MIN_F64: f64 = -9_223_372_036_854_775_808.0;
/// One past the largest `i64`: `i64::MAX as f64` rounds up to 2^63, so this
/// is the *exclusive* bound a scaled amount must stay under.
const I64_OVERFLOW_F64: f64 = 9_223_372_036_854_775_808.0;

/// ISO 4217 minor-unit exponents for active, decimal currencies. Fund codes
/// (`XAD`, `BOV`, `CHE`, `CHW`, `COU`, `MXV`, `USN`, `UYI`, `UYW`) are included
/// where ISO 4217 lists them as active entries with a published exponent.
/// Precious-metal (`XAU`/`XAG`/…), bond-market (`XBA`/…), reserved (`XTS`/`XXX`)
/// and the special drawing right `XDR` are deliberately absent: they are either
/// not currency denominations or have no decimal minor unit, and
/// [`currency_exponent`] returns `None` for them.
static ISO_4217_EXPONENTS: &[(&str, u8)] = &[
    ("AED", 2),
    ("AFN", 2),
    ("ALL", 2),
    ("AMD", 2),
    ("AOA", 2),
    ("ARS", 2),
    ("AUD", 2),
    ("AWG", 2),
    ("AZN", 2),
    ("BAM", 2),
    ("BBD", 2),
    ("BDT", 2),
    ("BHD", 3),
    ("BIF", 0),
    ("BMD", 2),
    ("BND", 2),
    ("BOB", 2),
    ("BOV", 2),
    ("BRL", 2),
    ("BSD", 2),
    ("BTN", 2),
    ("BWP", 2),
    ("BYN", 2),
    ("BZD", 2),
    ("CAD", 2),
    ("CDF", 2),
    ("CHE", 2),
    ("CHF", 2),
    ("CHW", 2),
    ("CLF", 4),
    ("CLP", 0),
    ("CNY", 2),
    ("COP", 2),
    ("COU", 2),
    ("CRC", 2),
    ("CUP", 2),
    ("CVE", 2),
    ("CZK", 2),
    ("DJF", 0),
    ("DKK", 2),
    ("DOP", 2),
    ("DZD", 2),
    ("EGP", 2),
    ("ERN", 2),
    ("ETB", 2),
    ("EUR", 2),
    ("FJD", 2),
    ("FKP", 2),
    ("GBP", 2),
    ("GEL", 2),
    ("GHS", 2),
    ("GIP", 2),
    ("GMD", 2),
    ("GNF", 0),
    ("GTQ", 2),
    ("GYD", 2),
    ("HKD", 2),
    ("HNL", 2),
    ("HTG", 2),
    ("HUF", 2),
    ("IDR", 2),
    ("ILS", 2),
    ("INR", 2),
    ("IQD", 3),
    ("IRR", 2),
    ("ISK", 0),
    ("JMD", 2),
    ("JOD", 3),
    ("JPY", 0),
    ("KES", 2),
    ("KGS", 2),
    ("KHR", 2),
    ("KMF", 0),
    ("KPW", 2),
    ("KRW", 0),
    ("KWD", 3),
    ("KYD", 2),
    ("KZT", 2),
    ("LAK", 2),
    ("LBP", 2),
    ("LKR", 2),
    ("LRD", 2),
    ("LSL", 2),
    ("LYD", 3),
    ("MAD", 2),
    ("MDL", 2),
    ("MGA", 2),
    ("MKD", 2),
    ("MMK", 2),
    ("MNT", 2),
    ("MOP", 2),
    ("MRU", 2),
    ("MUR", 2),
    ("MVR", 2),
    ("MWK", 2),
    ("MXN", 2),
    ("MXV", 2),
    ("MYR", 2),
    ("MZN", 2),
    ("NAD", 2),
    ("NGN", 2),
    ("NIO", 2),
    ("NOK", 2),
    ("NPR", 2),
    ("NZD", 2),
    ("OMR", 3),
    ("PAB", 2),
    ("PEN", 2),
    ("PGK", 2),
    ("PHP", 2),
    ("PKR", 2),
    ("PLN", 2),
    ("PYG", 0),
    ("QAR", 2),
    ("RON", 2),
    ("RSD", 2),
    ("RUB", 2),
    ("RWF", 0),
    ("SAR", 2),
    ("SBD", 2),
    ("SCR", 2),
    ("SDG", 2),
    ("SEK", 2),
    ("SGD", 2),
    ("SHP", 2),
    ("SLE", 2),
    ("SOS", 2),
    ("SRD", 2),
    ("SSP", 2),
    ("STN", 2),
    ("SVC", 2),
    ("SYP", 2),
    ("SZL", 2),
    ("THB", 2),
    ("TJS", 2),
    ("TMT", 2),
    ("TND", 3),
    ("TOP", 2),
    ("TRY", 2),
    ("TTD", 2),
    ("TWD", 2),
    ("TZS", 2),
    ("UAH", 2),
    ("UGX", 0),
    ("USD", 2),
    ("USN", 2),
    ("UYI", 0),
    ("UYU", 2),
    ("UYW", 4),
    ("UZS", 2),
    ("VED", 2),
    ("VES", 2),
    ("VND", 0),
    ("VUV", 0),
    ("WST", 2),
    ("XAD", 2),
    ("XAF", 0),
    ("XCD", 2),
    ("XCG", 2),
    ("XOF", 0),
    ("XPF", 0),
    ("YER", 2),
    ("ZAR", 2),
    ("ZMW", 2),
    ("ZWG", 2),
];

/// Look up `code` (case-insensitively) in the ISO 4217 table and return its
/// minor-unit exponent, or `None` if `code` is not a recognized active,
/// decimal currency (e.g. `XDR`, `XXX`, or a typo).
#[must_use]
pub fn currency_exponent(code: &str) -> Option<u8> {
    let upper = code.to_ascii_uppercase();
    ISO_4217_EXPONENTS
        .binary_search_by(|(c, _)| c.as_bytes().cmp(upper.as_bytes()))
        .ok()
        .map(|i| ISO_4217_EXPONENTS[i].1)
}

/// Errors raised by [`major_to_minor`]. No `Eq`: two of the variants carry
/// the offending `f64`, which has no total order.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum MoneyError {
    /// The amount was NaN or infinite and cannot be scaled to minor units.
    #[error("money amount is not finite: {0}")]
    NotFinite(f64),
    /// The currency code is not a recognized active, decimal ISO 4217 code.
    #[error("unknown currency code: {0}")]
    UnknownCurrency(String),
    /// The scaled minor-units value fell outside the `i64` range.
    #[error("scaled minor-units value is out of i64 range: {0}")]
    OutOfRange(f64),
}

/// Convert a major-unit amount (e.g. `9.99` dollars) into minor units (e.g.
/// `999` cents) for `currency`, rounding half-away-from-zero.
///
/// # Caveat
///
/// `amount` is an `f64`, so ties that are not exactly representable in binary
/// floating point do not round as the decimal literal suggests: `1.005` is
/// really ~1.004999999999999893… and therefore yields `100` minor units, not
/// `101`. Pass amounts that are already exact multiples of the minor unit when
/// the tie direction matters.
///
/// Negative amounts are allowed (`RevenueCat` refunds). The currency code is
/// matched case-insensitively.
///
/// # Errors
///
/// [`MoneyError::NotFinite`] for NaN/infinity, [`MoneyError::UnknownCurrency`]
/// for an unrecognized code, and [`MoneyError::OutOfRange`] when the scaled
/// value does not fit in an `i64`.
pub fn major_to_minor(amount: f64, currency: &str) -> Result<i64, MoneyError> {
    if !amount.is_finite() {
        return Err(MoneyError::NotFinite(amount));
    }
    let exponent = currency_exponent(currency)
        .ok_or_else(|| MoneyError::UnknownCurrency(currency.to_string()))?;
    let scaled = amount * 10f64.powi(exponent.into());
    if scaled < I64_MIN_F64 || scaled >= I64_OVERFLOW_F64 {
        return Err(MoneyError::OutOfRange(scaled));
    }
    // The two bounds above are what make this cast exact: `scaled` is a
    // whole-minor-unit value inside `[i64::MIN, i64::MAX]`.
    #[allow(clippy::cast_possible_truncation)]
    let minor = scaled.round() as i64;
    Ok(minor)
}

/// The charge decomposed into its parts, the way `RevenueCat`'s
/// `MonetaryAmount` reports them: gross, optional USD-normalized gross, tax,
/// processor fee and net, plus whether the parts were estimated locally rather
/// than reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeAmounts {
    /// The gross amount charged, in its own currency.
    pub gross: Money,
    /// The gross amount converted to USD, when the provider reports one.
    pub usd_gross: Option<Money>,
    /// The tax (VAT/sales tax) withheld, when known.
    pub tax: Option<Money>,
    /// The processor commission or fee withheld, when known.
    pub fee: Option<Money>,
    /// The net proceeds (`gross - fee - tax`), when known.
    pub net: Option<Money>,
    /// `true` when the tax/fee/net parts were derived locally (e.g. from
    /// percentages) rather than reported verbatim by the provider.
    pub estimated: bool,
}

impl ChargeAmounts {
    /// Build a [`ChargeAmounts`] from `gross` and the tax and commission
    /// shares of gross that `RevenueCat` documents (`proceeds = gross -
    /// commission - tax`). `tax_pct` and `commission_pct` are decimal
    /// fractions (`0.30` is 30%), not whole percentages, which is how
    /// `RevenueCat`'s `MonetaryAmount` reports them.
    ///
    /// The parts are rounded to the nearest minor unit (half-away-from-zero)
    /// and `estimated` is set to `true`. A non-finite share is treated as
    /// zero rather than allowed through `f64 as i64`'s saturating cast, and
    /// the net is computed with saturating arithmetic so a pathological
    /// gross cannot wrap around. Every currency code is lowercased, so a
    /// provider that reports `USD` yields the `"usd"` [`Money`] documents.
    #[must_use]
    pub fn from_percentages(gross: &Money, tax_pct: f64, commission_pct: f64) -> Self {
        let gross_minor = gross.minor_units;
        let currency = gross.currency.to_ascii_lowercase();
        let tax_minor = share_of(gross_minor, tax_pct);
        let fee_minor = share_of(gross_minor, commission_pct);
        let net_minor = gross_minor
            .saturating_sub(tax_minor)
            .saturating_sub(fee_minor);
        ChargeAmounts {
            gross: Money::new(gross_minor, currency.clone()),
            usd_gross: None,
            tax: Some(Money::new(tax_minor, currency.clone())),
            fee: Some(Money::new(fee_minor, currency.clone())),
            net: Some(Money::new(net_minor, currency)),
            estimated: true,
        }
    }
}

/// `fraction` of `minor_units`, rounded to the nearest whole minor unit
/// (half-away-from-zero), guarding the two things a bare `as i64` would
/// swallow: a non-finite fraction, and a product outside `i64`.
///
/// The scaling stays in minor units rather than going through
/// [`major_to_minor`]: the gross is already minor units, and
/// major-units-out-then-back-in would round twice.
fn share_of(minor_units: i64, fraction: f64) -> i64 {
    if !fraction.is_finite() {
        return 0;
    }
    #[allow(clippy::cast_precision_loss)]
    let scaled = (minor_units as f64) * fraction;
    if scaled >= I64_OVERFLOW_F64 || scaled < I64_MIN_F64 {
        return if scaled < 0.0 { i64::MIN } else { i64::MAX };
    }
    // Bounded by the two constants above, so the truncation is exact after
    // the round.
    #[allow(clippy::cast_possible_truncation)]
    let share = scaled.round() as i64;
    share
}

/// The kind of ledger row. A closed, code-owned set: a correction is a new
/// row, never a mutation of an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerKind {
    /// A charge captured (Stripe `charge.succeeded`; RC `INITIAL_PURCHASE`/`RENEWAL`).
    Charge,
    /// A refund issued (Stripe `charge.refunded`; RC `CANCELLATION` `CUSTOMER_SUPPORT`).
    Refund,
    /// A store refund later reversed (App Store; RC `REFUND_REVERSED`).
    RefundReversal,
    /// Disputed funds withdrawn (Stripe `charge.dispute.funds_withdrawn`).
    DisputeWithdrawal,
    /// A dispute fee charged by the card network.
    DisputeFee,
    /// Disputed funds reinstated after a won dispute (Stripe
    /// `charge.dispute.funds_reinstated`).
    DisputeReinstatement,
    /// A Stripe fee or settlement detail (issue #616).
    ProcessorFee,
    /// A manual adjustment.
    Adjustment,
}

/// One immutable row in the billing ledger (ADR 0025 decision 3, issue #594).
///
/// Ledger rows are never updated in place: a correction is a new row that
/// offsets the one it supersedes, referenced through `external_ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// This row's id.
    pub id: String,
    /// The account (customer) the row is posted to, when known.
    pub account_id: Option<String>,
    /// Which provider delivered the underlying event.
    pub provider: Provider,
    /// Which store the purchase came from.
    pub store: Store,
    /// Production or sandbox.
    pub environment: Environment,
    /// What kind of ledger row this is.
    pub kind: LedgerKind,
    /// The lifecycle event id this row was derived from.
    pub source_event_id: String,
    /// The provider's id for the charge/transaction, for reconciliation.
    pub external_ref: Option<String>,
    /// When the row says the money moved.
    pub occurred_at: OffsetDateTime,
    /// The decomposed charge amounts.
    pub amounts: ChargeAmounts,
    /// The product (or store SKU) the row concerns.
    pub product_id: Option<String>,
    /// The ISO-3166 country code, when the provider reports one.
    pub country: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponent_known_codes() {
        assert_eq!(currency_exponent("JPY"), Some(0));
        assert_eq!(currency_exponent("usd"), Some(2));
        assert_eq!(currency_exponent("KWD"), Some(3));
        assert_eq!(currency_exponent("CLF"), Some(4));
    }

    #[test]
    fn exponent_unknown_codes_are_none() {
        assert_eq!(currency_exponent("XDR"), None);
        assert_eq!(currency_exponent("ZZZ"), None);
        assert_eq!(currency_exponent("XXX"), None);
        assert_eq!(currency_exponent("XAU"), None);
    }

    /// The lookup is a binary search: a table that is unsorted, or that
    /// repeats a code, silently answers `None` for a real currency.
    #[test]
    fn exponent_table_is_sorted_and_free_of_duplicates() {
        assert!(
            ISO_4217_EXPONENTS.windows(2).all(|w| w[0].0 < w[1].0),
            "ISO_4217_EXPONENTS must be sorted by code with no duplicates"
        );
    }

    /// Every zero-decimal active currency, so a new row cannot silently
    /// pick the wrong exponent for the small-unit currencies.
    #[test]
    fn exponent_zero_decimal_currencies() {
        for code in [
            "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI",
            "VND", "VUV", "XAF", "XOF", "XPF",
        ] {
            assert_eq!(currency_exponent(code), Some(0), "{code}");
        }
    }

    /// The Gulf three-decimal currencies, and the two four-decimal ones.
    #[test]
    fn exponent_three_and_four_decimal_currencies() {
        for code in ["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"] {
            assert_eq!(currency_exponent(code), Some(3), "{code}");
        }
        for code in ["CLF", "UYW"] {
            assert_eq!(currency_exponent(code), Some(4), "{code}");
        }
    }

    /// `CLF` is the four-decimal fund of the family: the issue asks for it
    /// explicitly, since a two-decimal table would under-report it 100x.
    #[test]
    fn exponent_clf_is_four() {
        assert_eq!(currency_exponent("CLF"), Some(4));
        assert_eq!(currency_exponent("clf"), Some(4));
        assert_eq!(major_to_minor(9.9999, "clf"), Ok(99_999));
    }

    #[test]
    fn major_to_minor_usd() {
        assert_eq!(major_to_minor(9.99, "usd"), Ok(999));
    }

    #[test]
    fn major_to_minor_negative_usd() {
        assert_eq!(major_to_minor(-9.99, "usd"), Ok(-999));
    }

    #[test]
    fn major_to_minor_zero_exponent_jpy() {
        assert_eq!(major_to_minor(1200.0, "jpy"), Ok(1200));
    }

    #[test]
    fn major_to_minor_three_exponent_kwd_rounds_half_away_from_zero() {
        assert_eq!(major_to_minor(1.2345, "kwd"), Ok(1235));
    }

    #[test]
    fn major_to_minor_negative_kwd_rounds_away_from_zero() {
        assert_eq!(major_to_minor(-1.2345, "kwd"), Ok(-1235));
    }

    #[test]
    fn major_to_minor_out_of_i64_range_is_error() {
        assert!(matches!(
            major_to_minor(1e30, "usd"),
            Err(MoneyError::OutOfRange(_))
        ));
        assert!(matches!(
            major_to_minor(-1e30, "usd"),
            Err(MoneyError::OutOfRange(_))
        ));
    }

    /// A large-but-representable amount still converts, and one past the
    /// `i64` range must not: the check is `>=`, not `>`.
    #[test]
    fn major_to_minor_i64_boundary() {
        assert_eq!(
            major_to_minor(9_000_000_000_000.0, "usd"),
            Ok(900_000_000_000_000)
        );
        assert!(matches!(
            major_to_minor(1e17, "usd"),
            Err(MoneyError::OutOfRange(_))
        ));
    }

    #[test]
    fn major_to_minor_nan_is_error() {
        assert!(matches!(
            major_to_minor(f64::NAN, "usd"),
            Err(MoneyError::NotFinite(_))
        ));
    }

    #[test]
    fn major_to_minor_infinite_is_error() {
        assert!(matches!(
            major_to_minor(f64::INFINITY, "usd"),
            Err(MoneyError::NotFinite(_))
        ));
    }

    #[test]
    fn major_to_minor_unknown_currency_is_error() {
        assert!(matches!(
            major_to_minor(9.99, "zzz"),
            Err(MoneyError::UnknownCurrency(_))
        ));
    }

    #[test]
    fn charge_amounts_from_percentages_matches_revenuecat_sample() {
        let result =
            ChargeAmounts::from_percentages(&Money::new(999, "usd"), 0.75 / 9.99, 2.99 / 9.99);
        assert_eq!(result.tax, Some(Money::new(75, "usd")));
        assert_eq!(result.fee, Some(Money::new(299, "usd")));
        assert_eq!(result.net, Some(Money::new(625, "usd")));
        assert!(result.estimated);
        assert_eq!(result.usd_gross, None);
        assert_eq!(result.gross, Money::new(999, "usd"));
    }

    /// `RevenueCat` reports an uppercase code (`"USD"`); [`Money`] documents a
    /// lowercase one, so every part of the row is normalized.
    #[test]
    fn charge_amounts_lowercases_an_uppercase_currency() {
        let result = ChargeAmounts::from_percentages(&Money::new(999, "USD"), 0.1, 0.2);
        assert_eq!(result.gross.currency, "usd");
        assert_eq!(result.tax, Some(Money::new(100, "usd")));
        assert_eq!(result.fee, Some(Money::new(200, "usd")));
        assert_eq!(result.net, Some(Money::new(699, "usd")));
    }

    /// A non-finite share contributes nothing rather than wrapping through
    /// `f64 as i64`'s saturating cast into a plausible-looking number.
    #[test]
    fn charge_amounts_ignore_non_finite_percentages() {
        let result = ChargeAmounts::from_percentages(&Money::new(999, "usd"), f64::NAN, f64::NAN);
        assert_eq!(result.tax, Some(Money::new(0, "usd")));
        assert_eq!(result.fee, Some(Money::new(0, "usd")));
        assert_eq!(result.net, Some(Money::new(999, "usd")));
    }

    /// A share that would overflow `i64` saturates instead of wrapping, and
    /// the net stays a number rather than an overflowed negative.
    #[test]
    fn charge_amounts_saturate_rather_than_wrap() {
        let result = ChargeAmounts::from_percentages(&Money::new(i64::MAX, "usd"), 1.0, 1.0);
        assert_eq!(result.tax, Some(Money::new(i64::MAX, "usd")));
        assert_eq!(result.fee, Some(Money::new(i64::MAX, "usd")));
        assert_eq!(result.net, Some(Money::new(-i64::MAX, "usd")));
    }

    /// Half-away-from-zero, on both signs, at a two-decimal exponent.
    #[test]
    fn charge_amounts_round_half_away_from_zero() {
        let up = ChargeAmounts::from_percentages(&Money::new(101, "usd"), 0.5, 0.0);
        assert_eq!(up.tax, Some(Money::new(51, "usd")));
        let down = ChargeAmounts::from_percentages(&Money::new(-101, "usd"), 0.5, 0.0);
        assert_eq!(down.tax, Some(Money::new(-51, "usd")));
    }

    /// The ledger row carries no float: every stored amount is minor units.
    #[test]
    fn ledger_entry_holds_minor_units() {
        let entry = LedgerEntry {
            id: "led_1".to_string(),
            account_id: Some("acct_1".to_string()),
            provider: Provider::RevenueCat,
            store: Store::AppStore,
            environment: Environment::Sandbox,
            kind: LedgerKind::RefundReversal,
            source_event_id: "evt_1".to_string(),
            external_ref: Some("2000000123456789".to_string()),
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            amounts: ChargeAmounts::from_percentages(&Money::new(999, "USD"), 0.0, 0.0),
            product_id: Some("com.example.sub".to_string()),
            country: Some("US".to_string()),
        };
        assert_eq!(entry.amounts.gross, Money::new(999, "usd"));
        assert_eq!(entry.kind, LedgerKind::RefundReversal);
    }
}
