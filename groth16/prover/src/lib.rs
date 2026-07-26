//! Proving a zkICAO predicate with Groth16, in Rust.
//!
//! A holder proves on their own device, so the path a proof takes matters as
//! much as the circuit. This crate is that path: the circuit graph circom
//! emits, witness generation in Rust, and the proving key held once rather
//! than reloaded per proof. Nothing here runs a JavaScript or WebAssembly
//! runtime, which is the difference between a proof a phone can produce and
//! one it can only produce slowly.
//!
//! What this crate does not hold is any key material or any policy. The
//! proving key belongs to the deployment that ran its own phase 2 ceremony,
//! and the domain, the bounds and the sets belong to the verifier, so both
//! are arguments rather than constants.
//!
//! The proving step itself is delegated. Barretenberg does that job on the
//! UltraHonk side and rapidsnark does it here, in both cases because a hand
//! written prover would be a second implementation of something that is
//! already correct and much faster than a new one would be.

use std::collections::HashMap;

#[cfg(feature = "rapidsnark")]
pub mod prove;

pub mod witness;

/// Which statement a proof makes about a committed field. The names are the
/// instantiations under `bin/predicate/`, so a caller names the same
/// statement here that it would name in the Noir tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Statement {
    Compare,
    Member,
    Reveal,
}

impl Statement {
    pub fn name(self) -> &'static str {
        match self {
            Self::Compare => "compare",
            Self::Member => "member",
            Self::Reveal => "reveal",
        }
    }
}

/// The inputs a predicate takes, as field elements in decimal, keyed by the
/// signal names the circuit declares.
///
/// Decimal strings rather than integers because a field element does not fit
/// any Rust integer, and because it is the form both the witness calculator
/// and the circuit's own tooling take, so no conversion can lose a value.
pub type Inputs = HashMap<String, serde_json::Value>;

#[derive(Debug)]
pub enum Failure {
    /// The witness could not be solved, which means the inputs do not
    /// satisfy the circuit: an opening that does not belong to the
    /// commitment, or a value outside the range.
    Unsatisfied(String),

    /// The circuit graph could not be read.
    Graph(String),

    /// The inputs could not be serialised.
    Malformed(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsatisfied(reason) => {
                write!(f, "the inputs do not satisfy the circuit: {reason}")
            }
            Self::Graph(reason) => write!(f, "cannot read the circuit graph: {reason}"),
            Self::Malformed(reason) => write!(f, "the inputs are malformed: {reason}"),
        }
    }
}

impl std::error::Error for Failure {}
