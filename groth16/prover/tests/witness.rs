//! Solves a witness the way a holder's device would: from the circuit graph,
//! in Rust, with no JavaScript or WebAssembly runtime anywhere.
//!
//! The inputs are a commitment and a field opening the Noir circuits
//! produced, so this is the same agreement the circom side checks, reached
//! through the path a deployment would actually use.
//!
//! Skipped when the graph and the witness are not present, since building
//! them needs circom and a bundle run, neither of which this crate depends
//! on. Build them with:
//!
//!     build-circuit bin/predicate/compare/main.circom build/compare.graph
//!     cd ../../fixtures/generator && cargo run -- bundle

use std::path::{Path, PathBuf};

use zkicao_groth16::{witness::Circuit, Inputs, Statement};

fn groth16_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("unexpected crate location")
        .to_path_buf()
}

/// Reads the witness the Noir predicate was given and reshapes it into the
/// signal names the circom circuit declares.
fn opening() -> Option<Inputs> {
    let toml = groth16_root()
        .parent()?
        .join("bin/predicate/compare/Prover.toml");

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

#[test]
fn solves_a_witness_from_a_real_noir_opening() {
    let graph = groth16_root().join("build/compare.graph");

    let (Ok(bytes), Some(inputs)) = (std::fs::read(&graph), opening()) else {
        eprintln!("skipping: build the graph and run the bundle first");

        return;
    };

    let circuit = Circuit::new(Statement::Compare, bytes).expect("the graph loads");

    let witness = circuit
        .solve(&inputs)
        .expect("a real opening from the Noir circuits must satisfy the circom predicate");

    assert!(!witness.is_empty(), "the witness is empty");
}

// Where an invalid opening is caught, which is not where a reader would
// expect and is the single most important thing to know when integrating
// this path.
//
// The graph walker evaluates assignments and does not check constraints, so
// an opening that belongs to no commitment still yields a witness here. The
// JavaScript calculator does check them and refuses the same input, so the
// two paths disagree about when the failure appears, and only the JavaScript
// one matches the intuition that generating a witness validates it.
//
// The proof is where it surfaces on this path: proving over such a witness
// fails. So a caller must treat a produced witness as nothing more than a
// produced witness, and take the proof as the answer. This is the same shape
// as the Barretenberg property the Noir side records, where proving succeeds
// over an unsatisfied witness and verification is what fails.
#[test]
fn an_invalid_opening_still_produces_a_witness_here() {
    let graph = groth16_root().join("build/compare.graph");

    let (Ok(bytes), Some(mut inputs)) = (std::fs::read(&graph), opening()) else {
        eprintln!("skipping: build the graph and run the bundle first");

        return;
    };

    inputs.insert("commitment".to_string(), "1".into());

    let circuit = Circuit::new(Statement::Compare, bytes).expect("the graph loads");

    assert!(
        circuit.solve(&inputs).is_ok(),
        "the graph walker checks no constraints, so this is expected to solve; \
         if it now refuses, the crate has changed and the guidance above with it"
    );
}
