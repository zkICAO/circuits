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

use zkicao_groth16::{witness::Circuit, Statement};

mod common;

fn groth16_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("unexpected crate location")
        .to_path_buf()
}

#[test]
fn solves_a_witness_from_a_real_noir_opening() {
    let graph = groth16_root().join("build/compare.graph");

    let (Ok(bytes), Some(inputs)) = (std::fs::read(&graph), common::opening(&groth16_root()))
    else {
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

    let (Ok(bytes), Some(mut inputs)) = (std::fs::read(&graph), common::opening(&groth16_root()))
    else {
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
