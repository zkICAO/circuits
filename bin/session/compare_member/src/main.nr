// Two predicates of one session, verified recursively as one proof.
//
// A session with a single predicate presents it bare, because aggregation
// buys nothing there. With more than one, this circuit verifies them inside
// one proof: the commitment, the domain and the context are single witnesses
// placed into both inner public input arrays, so the two proofs cannot be
// about different documents, applications or sessions and still prove.
//
// The statement values stay public. A verifier reads the field identifiers,
// the bounds and the set root off this proof exactly as it would off the
// bare predicates, and the returned commitment is what it links against a
// registration, so this proof drops into the same place a predicate does.
//
// The verification key hashes are compiled in from a generated keys.nr, and
// the backend property recorded on the registration circuit applies here
// unchanged: proving does not check the witness, verification does.

mod keys;

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};

fn main(
    compare_key: UltraHonkVerificationKey,
    compare_proof: UltraHonkZKProof,
    member_key: UltraHonkVerificationKey,
    member_proof: UltraHonkZKProof,
    commitment: Field,
    compare_field_id: pub Field,
    minimum: pub Field,
    maximum: pub Field,
    member_field_id: pub Field,
    set_root: pub Field,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(domain != 0, "session: domain must be set");

    assert(context != 0, "session: context must be set");

    verify_honk_proof(
        compare_key,
        compare_proof,
        [compare_field_id, commitment, minimum, maximum, domain, context],
        keys::COMPARE,
    );

    verify_honk_proof(
        member_key,
        member_proof,
        [member_field_id, commitment, set_root, domain, context],
        keys::MEMBER,
    );

    commitment
}
