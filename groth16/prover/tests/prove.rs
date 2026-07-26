//! The whole path a holder's device takes, in Rust: a real opening from the
//! Noir circuits, a witness from the circuit graph, a proof from rapidsnark.
//!
//! Runs only with the rapidsnark feature and only when the artifacts are
//! there, since both need tools this crate does not depend on. The proof is
//! written out so that snarkjs can be asked whether it verifies, which is
//! the check that matters: producing a proof is not the same as producing a
//! valid one, on either stack.

#![cfg(feature = "rapidsnark")]

use std::path::{Path, PathBuf};

use zkicao_groth16::{prove::prove, witness::Circuit, Statement};

mod common;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("unexpected crate location")
        .to_path_buf()
}

#[test]
fn proves_a_real_opening_end_to_end() {
    let graph = root().join("build/compare.graph");

    let zkey = root().join("build/compare.zkey");

    let (Ok(graph), Ok(zkey), Some(inputs)) = (
        std::fs::read(&graph),
        std::fs::read(&zkey),
        common::opening(&root()),
    ) else {
        eprintln!("skipping: run tools/setup.sh, build the graph, and run the bundle");

        return;
    };

    let circuit = Circuit::new(Statement::Compare, graph).expect("the graph loads");

    let witness = circuit
        .solve(&inputs)
        .expect("a real opening from the Noir circuits must satisfy the predicate");

    let proof = prove(&zkey, &witness).expect("rapidsnark must prove a satisfied witness");

    assert!(proof.proof.contains("pi_a"), "not a Groth16 proof");

    // Five public signals: the field identifier, the commitment, the two
    // bounds and the domain.
    let signals: Vec<String> =
        serde_json::from_str(&proof.public_signals).expect("the signals are a JSON array");

    assert_eq!(signals.len(), 5, "the predicate publishes five values");

    // Left where snarkjs can be pointed at them.
    let out = root().join("build");

    std::fs::write(out.join("rust_proof.json"), &proof.proof).expect("cannot write the proof");

    std::fs::write(out.join("rust_public.json"), &proof.public_signals)
        .expect("cannot write the signals");
}

// A witness the graph walker produced from an opening that belongs to no
// commitment, carried as far as it goes.
//
// It goes all the way. The graph walker checks no constraints and rapidsnark
// checks none either: a proof comes out. Verification is what refuses it,
// which is the same place the Noir stack refuses its equivalent. So on both
// stacks the rule is one rule: a produced proof is not a valid proof, and
// only verifying answers the question.
#[test]
fn an_unsatisfied_witness_still_proves_and_fails_verification() {
    let graph = root().join("build/compare.graph");

    let zkey = root().join("build/compare.zkey");

    let (Ok(graph), Ok(zkey), Some(mut inputs)) = (
        std::fs::read(&graph),
        std::fs::read(&zkey),
        common::opening(&root()),
    ) else {
        return;
    };

    inputs.insert("commitment".to_string(), "1".into());

    let circuit = Circuit::new(Statement::Compare, graph).expect("the graph loads");

    let witness = circuit
        .solve(&inputs)
        .expect("the graph walker checks no constraints, so this still produces a witness");

    let forged = prove(&zkey, &witness)
        .expect("rapidsnark checks no constraints, so a proof is produced here");

    // Left where the check script can ask snarkjs whether it verifies, since
    // this crate does not verify and should not: the answer has to come from
    // the verifier a relying party would actually use.
    let out = root().join("build");

    std::fs::write(out.join("forged_proof.json"), &forged.proof).expect("cannot write the proof");

    std::fs::write(out.join("forged_public.json"), &forged.public_signals)
        .expect("cannot write the signals");
}
