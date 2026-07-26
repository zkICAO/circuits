//! Nullifier policy identifiers.
//!
//! A policy fixes which credential fields derive a holder's scoped
//! identifier, and therefore what uniqueness the resulting nullifier
//! actually guarantees. The identifier is hashed into the nullifier, so two
//! policies can never produce the same value for the same holder.
//!
//! It is not a public input. Each nullifier circuit hashes in the one
//! constant it implements, so what tells a verifier which guarantee it
//! received is the verification key it accepted, and nothing else. An
//! application must therefore accept exactly one nullifier verification key
//! per `domain`: accepting two lets one holder present two different
//! nullifiers, which defeats the uniqueness the nullifier exists to
//! provide.
//!
//! Identifiers encode a family and a version as `family * 1000 + version`.
//! A revision takes a new version and therefore a new identifier, so values
//! derived under the old policy stay distinct and every existing
//! registration has to be re-established rather than carried forward.
//!
//! One policy is implemented. A second family takes the next free number;
//! reserving identifiers for policies that have no derivation would promise
//! guarantees this library cannot make.

// Document number and issuing state. Unique per document, but a holder who
// is issued a replacement document produces a different nullifier, because
// the secret behind it is the signature on the document that was replaced.
pub global DOCUMENT_NUMBER_V1: Field = 1001;
