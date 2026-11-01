//! Release-signing authorities. The auto-update path (`qclient`/node release
//! download) trusts a binary only when a quorum of these Ed448 public keys have
//! signed its `.dgst` digest file. Port of Go `config.Signatories`
//! (`config/config.go:151`); the hex strings are the canonical published keys.

/// The Ed448 public keys (hex) whose quorum signs release digests. Port of Go
/// `config.Signatories` (`config/config.go:151`).
pub const SIGNATORIES: [&str; 17] = [
    "b1214da7f355f5a9edb7bcc23d403bdf789f070cca10db2b4cadc22f2d837afb650944853e35d5f42ef3c4105b802b144b4077d5d3253e4100",
    "de4cfe7083104bfe32f0d4082fa0200464d8b10804a811653eedda376efcad64dd222f0f0ceb0b8ae58abe830d7a7e3f3b2d79d691318daa00",
    "540237a35e124882d6b64e7bb5718273fa338e553f772b77fe90570e45303762b34131bdcb6c0b9f2cf9e393d9c7e0f546eeab0bcbbd881680",
    "fbe4166e37f93f90d2ebf06305315ae11b37e501d09596f8bde11ba9d343034fbca80f252205aa2f582a512a72ad293df371baa582da072900",
    "4160572e493e1bf15c44e055b11bf75230c76c7d2c67b48066770ab03dfd5ed34c97b9a431ec18578c83a0df9250b8362c38068650e8b01400",
    "45170b626884b85d61ae109f2aa9b0e1ecc18b181508431ea6308f3869f2adae49da9799a0a594eaa4ef3ad492518fb1729decd44169d40d00",
    "92cd8ee5362f3ae274a75ab9471024dbc144bff441ed8af7d19750ac512ff51e40e7f7b01e4f96b6345dd58878565948c3eb52c53f250b5080",
    "001a4cbfce5d9aeb7e20665b0d236721b228a32f0baee62ffa77f45b82ecaf577e8a38b7ef91fcf7d2d2d2b504f085461398d30b24abb1d700",
    "65b835071731c6e785bb2d107c7d85d8a537d79c435c3f42bb2f87027f93f858d7b37c598cef267a5db46e345f7a6f81969b465686657d1e00",
    "b6df0ebab6ea20cc2eb718db5873c07bb50cf239a16bb6306bbe0f24280664f99f732c4049b8eda1226067e70ffb81958834d486942a122100",
    "3e087771c36098cb2d371711fd882d309b4caebbd06ded3077a975231344f027ad31c7069e76ba5070451d8eb5abf29bfeb34fcdf9ba906480",
    "57be2861faf0fffcbfd122c85c77010dce8f213030905781b85b6f345d912c7b5ace17797d9810899dfb8d13e7c8369595740725ab3dd5bd00",
    "61628beef8f6964466fd078d6a2b90a397ab0777a14b9728227fd19f36752f9451b1a8d780740a0b9a8ce3df5f89ca7b9ff17de9274a270980",
    "9ab76d775487c85c8e5aa0c5b3f961772967899a14644651031ae5f98ac197bee3f8880492c4fdba268716fc4b7c38ffcac370b663ac10b600",
    "c0d2d47d6309572a055abf593de26a8c980be04df9672ed40939f93b51806be53f6e58f330ff348592350783d24109fa7db8bf7e61c9a8b780",
    "6e2872f73c4868c4286bef7bfe2f5479a41c42f4e07505efa4883c7950c740252e0eea78eef10c584b19b1dcda01f7767d3135d07c33244100",
    "0ca6f5a9d7f86c1111be5edf31e26979918aa4fa3daae6de1120e05c2a09bdb8d2feeb084286a3347e06ced25530358cbc74c204d2a1753a00",
];

/// The number of valid signatory signatures a release digest needs to be
/// trusted. Matches Go's threshold: `((n - 4) / 2) + ((n - 4) % 2)` — i.e.
/// ceil((n-4)/2), tolerating up to 4 unavailable signers. For the 17 canonical
/// signatories this is 7.
pub fn signatory_quorum() -> usize {
    let n = SIGNATORIES.len();
    ((n - 4) / 2) + ((n - 4) % 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_is_seven_for_seventeen_signatories() {
        assert_eq!(SIGNATORIES.len(), 17);
        assert_eq!(signatory_quorum(), 7);
    }
}
