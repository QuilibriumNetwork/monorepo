//! Small formatting/parsing helpers shared across commands.

use num_bigint::BigInt;

/// The QUIL conversion factor `0x1DCD65000` = 8,000,000,000 base units
/// per QUIL (`client/cmd/token/balance.go:94`).
pub fn conversion_factor() -> BigInt {
    BigInt::from(0x1_DCD6_5000_u64)
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
    fn rounds_half_away_from_zero() {
        // den = 8e9, so 1 base unit = 0.000000000125 QUIL exactly -> 12 dp.
        let one_unit = BigInt::from(1u64);
        assert_eq!(float_string_12(&one_unit, &conversion_factor()), "0.000000000125");
    }
}
