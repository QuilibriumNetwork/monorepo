//! Fee movement allowed between a confirmation and the submit that follows.

use quil_client::commands::token::AgentQuote;

/// Why a fresh quote cannot use the confirmation the operator already gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteDrift {
    /// The new automatic fee is above `--max-fee`.
    AboveMax { latest: u128, max_fee: u128 },
    /// The new fee rose by more than the configured slippage.
    BeyondSlippage {
        confirmed: u128,
        latest: u128,
        ceiling: u128,
    },
    /// A node-read amount (a mint reward) came back lower.
    AmountFell { confirmed: u128, latest: u128 },
}

impl std::fmt::Display for QuoteDrift {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AboveMax { latest, max_fee } => write!(
                formatter,
                "the new fee of {latest} base units exceeds the automatic cap of {max_fee} base units"
            ),
            Self::BeyondSlippage {
                confirmed,
                latest,
                ceiling,
            } => write!(
                formatter,
                "the fee moved from {confirmed} to {latest} base units, past the allowance of {ceiling}"
            ),
            Self::AmountFell { confirmed, latest } => write!(
                formatter,
                "the amount fell from {confirmed} to {latest} base units"
            ),
        }
    }
}

/// `latest` may replace `confirmed` when its fee did not rise past slippage
/// or the automatic cap, and any node-read amount did not fall.
///
/// A fee the operator named does not move. A lower quoted fee is inside the
/// allowance. Slippage is in basis points (200 is 2%).
pub fn accept_requote(
    confirmed: &AgentQuote,
    latest: &AgentQuote,
    slippage_bps: u32,
) -> Result<(), QuoteDrift> {
    if let (Some(was), Some(now)) = (confirmed.variable_amount, latest.variable_amount) {
        if now < was {
            return Err(QuoteDrift::AmountFell {
                confirmed: was,
                latest: now,
            });
        }
    }
    if confirmed.fee_explicit {
        return Ok(());
    }
    let was = confirmed.fee.unwrap_or(0);
    let now = latest.fee.unwrap_or(0);
    if now > confirmed.max_fee {
        return Err(QuoteDrift::AboveMax {
            latest: now,
            max_fee: confirmed.max_fee,
        });
    }
    let room = was.saturating_mul(u128::from(slippage_bps)) / 10_000;
    let ceiling = was.saturating_add(room);
    if now > ceiling {
        return Err(QuoteDrift::BeyondSlippage {
            confirmed: was,
            latest: now,
            ceiling,
        });
    }
    Ok(())
}

/// `200` basis points is `2%`. `25` is `0.25%`.
pub fn slippage_percent(slippage_bps: u32) -> String {
    let whole = slippage_bps / 100;
    let frac = slippage_bps % 100;
    if frac == 0 {
        format!("{whole}%")
    } else {
        format!("{whole}.{frac:02}%")
    }
}

/// The preview plus the exact command that approves it on this computer.
pub fn confirmation_text(quote: &AgentQuote, confirm_id: &str, slippage_bps: u32) -> String {
    let band = if quote.fee_explicit {
        "The fee is the one named above.".to_string()
    } else if slippage_bps == 0 {
        "Any higher fee needs a new confirmation.".to_string()
    } else {
        format!(
            "A later fee at or below this one, or up to {} higher and still within the automatic cap, can be submitted with this confirmation.",
            slippage_percent(slippage_bps)
        )
    };
    let mut text = format!("{}\n", quote.text);
    if let Some(amount) = quote.variable_amount {
        text.push_str(&money_line("Amount", amount));
    }
    if let Some(fee) = quote.fee {
        text.push_str(&money_line("Fee", fee));
    }
    text.push_str("  1 QUIL = 8000000000 base units.\n");
    text.push_str(&format!("  {band}\n"));
    text.push_str("  Nothing has been sent.\n");
    text.push_str(&format!("  Confirm this id to submit: {confirm_id}\n"));
    text.push_str(&format!(
        "  To approve it on this computer, run:\n    qagent confirm {confirm_id}\n"
    ));
    text.push_str(
        "  The assistant was not given this id. If you did not ask for this, do nothing. It expires in 10 minutes.\n",
    );
    text
}

fn money_line(label: &str, units: u128) -> String {
    format!(
        "  {label}: {} QUIL ({units} base units).\n",
        quil_client::util::format_quil(&units.to_be_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(fee: u128, explicit: bool, amount: Option<u128>) -> AgentQuote {
        AgentQuote {
            submits: true,
            text: String::new(),
            fee: Some(fee),
            fee_explicit: explicit,
            max_fee: 1_000,
            variable_amount: amount,
        }
    }

    #[test]
    fn a_fee_inside_slippage_and_under_the_cap_is_accepted() {
        let confirmed = quote(1_000, false, None);
        assert!(accept_requote(&confirmed, &quote(1_000, false, None), 200).is_ok());
        assert!(accept_requote(&confirmed, &quote(1_020, false, None), 200).is_ok());
        assert!(accept_requote(&confirmed, &quote(900, false, None), 0).is_ok());
    }

    #[test]
    fn a_fee_past_slippage_or_the_cap_is_refused() {
        let confirmed = quote(1_000, false, None);
        assert!(matches!(
            accept_requote(&confirmed, &quote(1_021, false, None), 200),
            Err(QuoteDrift::BeyondSlippage { .. })
        ));
        let mut over = quote(1_001, false, None);
        over.max_fee = 1_000;
        let mut confirmed = quote(900, false, None);
        confirmed.max_fee = 1_000;
        assert!(matches!(
            accept_requote(&confirmed, &over, 10_000),
            Err(QuoteDrift::AboveMax { .. })
        ));
    }

    #[test]
    fn an_explicit_fee_does_not_use_the_band_and_a_lower_reward_does() {
        let confirmed = quote(50, true, Some(80));
        assert!(accept_requote(&confirmed, &quote(80, true, Some(90)), 0).is_ok());
        assert!(matches!(
            accept_requote(&confirmed, &quote(50, true, Some(79)), 200),
            Err(QuoteDrift::AmountFell { .. })
        ));
    }

    #[test]
    fn slippage_percents_and_the_confirmation_name_the_id() {
        assert_eq!(slippage_percent(200), "2%");
        assert_eq!(slippage_percent(25), "0.25%");
        let text = confirmation_text(&quote(8_000_000_000, false, None), "abc", 200);
        assert!(text.contains("Confirm this id to submit: abc"), "{text}");
        assert!(text.contains("qagent confirm abc"), "{text}");
        assert!(text.contains("1.000000000000 QUIL"), "{text}");
        assert!(text.contains("8000000000 base units"), "{text}");
        assert!(text.contains("2%"), "{text}");
        assert!(text.contains("Nothing has been sent."), "{text}");
    }
}
