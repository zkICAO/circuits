//! Witness generation from the circuit graph, in memory.
//!
//! circom emits a graph beside the circuit; `circom-witnesscalc` walks it and
//! returns the witness as bytes. The graph is read once and held, because
//! rereading it per proof is the difference between a device that answers a
//! verifier in a second and one that does not.
//!
//! Nothing is written to disk. A witness is the holder's private material,
//! and a file of it left behind is the thing the commitment exists to
//! prevent being disclosed.

use crate::{Failure, Inputs, Statement};

/// A circuit's graph, loaded once and used for every proof it makes.
pub struct Circuit {
    statement: Statement,
    graph: Vec<u8>,
}

impl Circuit {
    /// Takes the graph bytes rather than a path, so a caller can embed it,
    /// hold it in an asset bundle, or read it from wherever it keeps one.
    pub fn new(statement: Statement, graph: Vec<u8>) -> Result<Self, Failure> {
        if graph.is_empty() {
            return Err(Failure::Graph(format!(
                "the graph for {} is empty",
                statement.name()
            )));
        }

        Ok(Self { statement, graph })
    }

    pub fn statement(&self) -> Statement {
        self.statement
    }

    /// Solves the witness for one set of inputs.
    ///
    /// A failure here is the useful one: it means the inputs do not satisfy
    /// the circuit, so the opening does not belong to the commitment or the
    /// value is outside the bounds. That is a real answer, not an error to
    /// be retried.
    pub fn solve(&self, inputs: &Inputs) -> Result<Vec<u8>, Failure> {
        let json = serde_json::to_string(inputs).map_err(|e| Failure::Malformed(e.to_string()))?;

        circom_witnesscalc::calc_witness(&json, &self.graph)
            .map_err(|e| Failure::Unsatisfied(e.to_string()))
    }
}
