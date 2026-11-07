//! What an assistant should do next. Amounts are QUIL. Addresses and
//! confirmation ids are never included.

/// One quote already held on this computer, described without its id.
pub struct HeldQuote {
    pub action: String,
    pub amount_quil: Option<String>,
}

/// The decision list. `balance` is the `token balance` text, which may be
/// missing when that read failed.
pub fn advise(balance: Option<&str>, held: &[HeldQuote], warnings: &[String]) -> String {
    let mut lines = Vec::new();
    for quote in held {
        lines.push(match &quote.amount_quil {
            Some(amount) => format!(
                "A {} quote for {amount} QUIL is already on the qagent terminal. Do not ask for another. Do not invent a confirmation id.",
                quote.action
            ),
            None => format!(
                "A {} quote is already on the qagent terminal. Do not ask for another. Do not invent a confirmation id.",
                quote.action
            ),
        });
    }
    match balance {
        Some(text) => lines.extend(from_balance(text)),
        None => lines.push(
            "Balance could not be read, so this does not say whether to mint or shield.".into(),
        ),
    }
    if !warnings.is_empty() {
        lines.push("Latest warnings:".into());
        for warning in warnings.iter().take(5) {
            lines.push(format!("- {warning}"));
        }
    }
    if lines.is_empty() {
        "Nothing is waiting. No quote is on the qagent terminal.".into()
    } else {
        lines.join("\n")
    }
}

fn from_balance(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("mint to claim") && !lower.contains("unavailable") && !lower.contains("none")
        {
            lines.push(
                "Claimable rewards are ready to mint. The next step is mint_quote. The amount is printed on the qagent terminal, not here.".into(),
            );
        } else if lower.contains("shield to spend") && !lower.contains("unavailable") {
            let detail = line
                .split_once(':')
                .map(|(_, rest)| rest.trim().trim_end_matches('.'))
                .unwrap_or(line);
            lines.push(format!(
                "Unshielded coins are waiting: {detail}. The next step is shield_quote. Do not invent a coin address."
            ));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advice_names_the_action_and_amount_and_hides_the_id_and_address() {
        let text = advise(
            Some(
                "Claimable rewards: 1.5 QUIL, mint to claim\n\
                 Unshielded legacy coins: 0.5 QUIL in 2 coins, shield to spend\n\
                 Confidential QUIL coins: none",
            ),
            &[HeldQuote {
                action: "transfer".into(),
                amount_quil: Some("1.000000000000".into()),
            }],
            &[],
        );
        assert!(text.contains("transfer quote for 1.000000000000 QUIL"), "{text}");
        assert!(text.contains("Do not invent a confirmation id"), "{text}");
        assert!(text.contains("mint_quote"), "{text}");
        assert!(text.contains("shield_quote"), "{text}");
        assert!(text.contains("0.5 QUIL in 2 coins"), "{text}");
        assert!(!text.contains("0x"), "{text}");
        assert!(!text.contains("confirm "), "{text}");
    }

    #[test]
    fn an_idle_balance_says_nothing_is_waiting() {
        let text = advise(
            Some("Claimable rewards: none\nUnshielded legacy coins: none\n"),
            &[],
            &[],
        );
        assert_eq!(text, "Nothing is waiting. No quote is on the qagent terminal.");
    }
}
