//! Proving with rapidsnark, over its C interface.
//!
//! The proof itself is delegated rather than reimplemented, for the same
//! reason the Noir side delegates to Barretenberg: a hand written Groth16
//! prover would be a second implementation of something already correct and
//! far faster than a new one would be. rapidsnark is the fast one, so it is
//! the one bound here.
//!
//! Everything stays in memory. A proving key and a witness are the two
//! things a holder must not leave on disk, and the C interface takes both as
//! buffers, so nothing here writes a file.
//!
//! The library is not on crates.io and has to be built for the host, so this
//! module is behind the `rapidsnark` feature. Without it the crate still
//! generates witnesses, which is the half that has no native dependency.

use std::ffi::{c_char, c_void};

use crate::Failure;

// The error codes prover.h defines. Anything but zero is a failure, and the
// two that are distinguished say something a caller can act on.
const PROVER_OK: i32 = 0;

const PROVER_ERROR_SHORT_BUFFER: i32 = 2;

const PROVER_INVALID_WITNESS_LENGTH: i32 = 3;

const ERROR_MESSAGE_CAPACITY: usize = 1024;

// How this is linked is build.rs's to say, not this attribute's: naming
// it here as well resolved to the dynamic library that ships beside the
// archive, and a proving key loaded through a dylib the deployment did not
// ship is a dependency nobody declared.
extern "C" {
    fn groth16_prover(
        zkey_buffer: *const c_void,
        zkey_size: u64,
        wtns_buffer: *const c_void,
        wtns_size: u64,
        proof_buffer: *mut c_char,
        proof_size: *mut u64,
        public_buffer: *mut c_char,
        public_size: *mut u64,
        error_msg: *mut c_char,
        error_msg_maxsize: u64,
    ) -> i32;
}

/// A proof and the public signals it was made over, both as JSON, which is
/// the form snarkjs and the generated Solidity verifier take.
pub struct Proof {
    pub proof: String,
    pub public_signals: String,
}

/// Proves one statement.
///
/// The proving key belongs to the deployment that ran its own phase 2
/// ceremony, so it is an argument. Holding it across calls is the caller's
/// job and is worth doing: reading it per proof is most of the cost.
///
/// A witness that does not satisfy the circuit fails here rather than
/// earlier, because the graph walker that produced it checks no constraints.
/// That failure is the real answer to an opening that belongs to no
/// commitment.
pub fn prove(zkey: &[u8], witness: &[u8]) -> Result<Proof, Failure> {
    // The sizes the library needs are not known in advance, so the first
    // call asks and the second fills. Starting large enough for a Groth16
    // proof and a handful of signals usually settles it in one.
    let mut proof = vec![0i8; 8 * 1024];

    let mut public_signals = vec![0i8; 8 * 1024];

    for attempt in 0..2 {
        let mut proof_size = proof.len() as u64;

        let mut public_size = public_signals.len() as u64;

        let mut error = vec![0i8; ERROR_MESSAGE_CAPACITY];

        let code = unsafe {
            groth16_prover(
                zkey.as_ptr() as *const c_void,
                zkey.len() as u64,
                witness.as_ptr() as *const c_void,
                witness.len() as u64,
                proof.as_mut_ptr(),
                &mut proof_size,
                public_signals.as_mut_ptr(),
                &mut public_size,
                error.as_mut_ptr(),
                ERROR_MESSAGE_CAPACITY as u64,
            )
        };

        match code {
            PROVER_OK => {
                return Ok(Proof {
                    proof: text(&proof, proof_size),
                    public_signals: text(&public_signals, public_size),
                })
            }

            // The library reports how much room it needed, so the second
            // attempt cannot be short. A third would mean the library is not
            // reporting sizes, which is not a case to loop on.
            PROVER_ERROR_SHORT_BUFFER if attempt == 0 => {
                proof.resize(proof_size as usize, 0);

                public_signals.resize(public_size as usize, 0);
            }

            PROVER_INVALID_WITNESS_LENGTH => {
                return Err(Failure::Unsatisfied(
                    "the witness does not have the length this proving key expects, \
                     so it was produced for another circuit"
                        .to_string(),
                ))
            }

            _ => return Err(Failure::Unsatisfied(message(&error))),
        }
    }

    Err(Failure::Unsatisfied(
        "rapidsnark asked for a larger buffer twice".to_string(),
    ))
}

/// The library writes a null terminated string into a buffer that may be
/// larger than the string, and the size it reports back is the buffer's
/// rather than the text's, so the terminator is what marks the end.
fn text(buffer: &[i8], size: u64) -> String {
    let bounded = &buffer[..(size as usize).min(buffer.len())];

    message(bounded)
}

fn message(buffer: &[i8]) -> String {
    let bytes: Vec<u8> = buffer.iter().map(|b| *b as u8).collect();

    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());

    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
