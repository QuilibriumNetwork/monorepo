//! Small formatting/parsing helpers shared across commands.

use num_bigint::BigInt;

/// The QUIL conversion factor `0x1DCD65000` = 8,000,000,000 base units
/// per QUIL (`client/cmd/token/balance.go:94`).
pub fn conversion_factor() -> BigInt {
    BigInt::from(0x1_DCD6_5000_u64)
}

/// Parse a user-entered **decimal QUIL** amount (integer or fractional, e.g.
/// `2`, `1.5`, `0.02`) into base units, as a non-negative [`BigInt`].
///
/// Mirrors the Go client's shopspring-decimal path:
/// `decimal.NewFromString(s).Mul(decimal.NewFromBigInt(conversionFactor,0)).BigInt()`
/// (`client/cmd/token/{transfer,split}.go`). The multiply is exact and the
/// final `.BigInt()` truncates the fractional base unit toward zero; since we
/// reject negatives, that is a plain floor. So `0.000000001` QUIL → 8 base
/// units, and sub-base-unit dust (e.g. `0.0000000001`) truncates to 0.
pub fn parse_quil_amount_bigint(s: &str) -> anyhow::Result<BigInt> {
    let t = s.trim();
    if t.is_empty() {
        anyhow::bail!("invalid amount: empty");
    }
    if t.starts_with('-') {
        anyhow::bail!("amount must not be negative: {s}");
    }
    let t = t.strip_prefix('+').unwrap_or(t);
    let (int_part, frac_part) = match t.split_once('.') {
        Some((i, f)) => (i, f),
        None => (t, ""),
    };
    // Reject `.`, empty operands where both sides are empty, and non-digits.
    if int_part.is_empty() && frac_part.is_empty() {
        anyhow::bail!("invalid amount (expected a decimal QUIL value like 1 or 1.5): {s}");
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        anyhow::bail!("invalid amount (expected a decimal QUIL value like 1 or 1.5): {s}");
    }

    // decimal value = mantissa / 10^scale, where mantissa is the concatenation
    // of the integer and fractional digits. base units = mantissa * 8e9 / 10^scale.
    let mantissa_str = format!("{int_part}{frac_part}");
    let mantissa: BigInt = if mantissa_str.is_empty() {
        BigInt::from(0)
    } else {
        mantissa_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid amount: {s}"))?
    };
    let scale = frac_part.len() as u32;
    let numerator = &mantissa * conversion_factor();
    let denom = BigInt::from(10).pow(scale);
    Ok(numerator / denom) // floor for non-negative == truncate toward zero
}

/// Like [`parse_quil_amount_bigint`] but returns `u128` base units for the
/// command paths that carry amounts as `u128`. Errors if the value doesn't fit.
pub fn parse_quil_amount(s: &str) -> anyhow::Result<u128> {
    let v = parse_quil_amount_bigint(s)?;
    u128::try_from(v).map_err(|_| anyhow::anyhow!("amount out of range for u128: {s}"))
}

/// Format `num/den` with exactly 12 fractional digits, rounding half away
/// from zero. Mirrors Go's `big.Rat.SetFrac(num, den).FloatString(12)`.
///
/// Inputs here are always non-negative (token amounts), but the rounding
/// is implemented generally.
pub fn float_string_12(num: &BigInt, den: &BigInt) -> String {
    const PREC: u32 = 12;
    let scale = BigInt::from(10).pow(PREC);

    let negative = (num.sign() == num_bigint::Sign::Minus) ^ (den.sign() == num_bigint::Sign::Minus);
    let num_abs = num.magnitude();
    let den_abs = den.magnitude();
    let num_abs = BigInt::from(num_abs.clone());
    let den_abs = BigInt::from(den_abs.clone());

    // scaled = round(num_abs * 10^PREC / den_abs), half away from zero.
    let numerator = &num_abs * &scale;
    let q = &numerator / &den_abs;
    let r = &numerator % &den_abs;
    let q = if &r * 2 >= den_abs { q + 1 } else { q };

    let int_part = &q / &scale;
    let frac_part = &q % &scale;
    let frac_str = format!("{:0>width$}", frac_part.to_string(), width = PREC as usize);

    let sign = if negative && (int_part != BigInt::from(0) || frac_part != BigInt::from(0)) {
        "-"
    } else {
        ""
    };
    format!("{sign}{int_part}.{frac_str}")
}

/// Format a big-endian base-unit amount as a QUIL decimal string with 12
/// fractional digits.
pub fn format_quil(amount_be: &[u8]) -> String {
    let amount = BigInt::from_bytes_be(num_bigint::Sign::Plus, amount_be);
    float_string_12(&amount, &conversion_factor())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_quil_is_eight_billion_base_units() {
        // 0x1DCD65000 base units == 1.000000000000 QUIL
        let one = conversion_factor();
        let (_, be) = one.to_bytes_be();
        assert_eq!(format_quil(&be), "1.000000000000");
    }

    #[test]
    fn zero() {
        assert_eq!(format_quil(&[]), "0.000000000000");
        assert_eq!(format_quil(&[0]), "0.000000000000");
    }

    #[test]
    fn half_quil() {
        // 4e9 base units == 0.5 QUIL
        let half = BigInt::from(4_000_000_000_u64);
        let (_, be) = half.to_bytes_be();
        assert_eq!(format_quil(&be), "0.500000000000");
    }

    #[test]
    fn parse_decimal_quil_amounts() {
        // 1 QUIL == 8e9 base units.
        assert_eq!(parse_quil_amount("1").unwrap(), 8_000_000_000);
        // 2 QUIL.
        assert_eq!(parse_quil_amount("2").unwrap(), 16_000_000_000);
        // 1.5 QUIL == 12e9.
        assert_eq!(parse_quil_amount("1.5").unwrap(), 12_000_000_000);
        // 0.5 QUIL == 4e9.
        assert_eq!(parse_quil_amount("0.5").unwrap(), 4_000_000_000);
        // 0.02 QUIL == 160e6.
        assert_eq!(parse_quil_amount("0.02").unwrap(), 160_000_000);
        // Smallest representable step: 0.000000001 QUIL == 8 base units.
        assert_eq!(parse_quil_amount("0.000000001").unwrap(), 8);
        // Sub-base-unit dust truncates toward zero (matches Go .BigInt()).
        assert_eq!(parse_quil_amount("0.0000000001").unwrap(), 0);
        // Zero is allowed at parse time.
        assert_eq!(parse_quil_amount("0").unwrap(), 0);
        // Leading-dot / trailing-dot forms.
        assert_eq!(parse_quil_amount(".5").unwrap(), 4_000_000_000);
        assert_eq!(parse_quil_amount("1.").unwrap(), 8_000_000_000);
    }

    #[test]
    fn parse_rejects_bad_amounts() {
        assert!(parse_quil_amount("").is_err());
        assert!(parse_quil_amount("-1").is_err());
        assert!(parse_quil_amount("abc").is_err());
        assert!(parse_quil_amount("1.2.3").is_err());
        assert!(parse_quil_amount(".").is_err());
    }

    #[test]
    fn rounds_half_away_from_zero() {
        // den = 8e9, so 1 base unit = 0.000000000125 QUIL exactly -> 12 dp.
        let one_unit = BigInt::from(1u64);
        assert_eq!(float_string_12(&one_unit, &conversion_factor()), "0.000000000125");
    }
}
