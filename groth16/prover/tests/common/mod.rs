//! Reads the witness the Noir predicate was given, shared by the tests that
//! need one.

use std::path::Path;

use zkicao_groth16::Inputs;

/// Reads the witness the Noir predicate was given and reshapes it into the
/// signal names the circom circuit declares.
pub fn opening(root: &Path) -> Option<Inputs> {
    let toml = root.parent()?.join("bin/predicate/compare/Prover.toml");

    let text = std::fs::read_to_string(toml).ok()?;

    let number = |raw: &str| -> String {
        let trimmed = raw.trim().trim_matches('"');

        if let Some(hex) = trimmed.strip_prefix("0x") {
            u128::from_str_radix(hex, 16)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| big_decimal(hex))
        } else {
            trimmed.to_string()
        }
    };

    let field = |name: &str| -> Option<String> {
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("{name} = ")))?;

        Some(number(line.split_once(" = ")?.1))
    };

    let list = |name: &str| -> Option<Vec<String>> {
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("{name} = [")))?;

        let body = line.split_once('[')?.1.rsplit_once(']')?.0;

        Some(
            body.split(',')
                .map(str::trim)
                .filter(|piece| !piece.is_empty())
                .map(number)
                .collect(),
        )
    };

    let mut inputs = Inputs::new();

    for (signal, name) in [
        ("fieldId", "field_id"),
        ("commitment", "commitment"),
        ("minimum", "minimum"),
        ("maximum", "maximum"),
        ("domain", "domain"),
        ("length", "length"),
        ("entropy", "entropy"),
    ] {
        inputs.insert(signal.to_string(), field(name)?.into());
    }

    for (signal, name) in [("data", "data"), ("siblings", "siblings")] {
        inputs.insert(signal.to_string(), list(name)?.into());
    }

    Some(inputs)
}

/// A field element is wider than any Rust integer, so a hex value that does
/// not fit is converted digit by digit.
fn big_decimal(hex: &str) -> String {
    // Base 10^9 limbs, multiplied in 64 bits because a limb times sixteen
    // does not fit 32.
    let mut digits = vec![0u64];

    for character in hex.chars() {
        let mut carry = character.to_digit(16).expect("not a hex digit") as u64;

        for digit in digits.iter_mut() {
            let product = *digit * 16 + carry;

            *digit = product % 1_000_000_000;

            carry = product / 1_000_000_000;
        }

        while carry > 0 {
            digits.push(carry % 1_000_000_000);

            carry /= 1_000_000_000;
        }
    }

    let mut out = digits.pop().expect("at least one limb").to_string();

    while let Some(limb) = digits.pop() {
        out.push_str(&format!("{limb:09}"));
    }

    out
}
