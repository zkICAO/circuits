// One recursive proof that a whole document chain holds.
//
// Verifies four proofs inside the circuit: Passive Authentication, a data
// group extraction, an attribute commitment and a signer inclusion. Their
// linkage is not a checklist here: each shared value appears once as a
// witness and is placed into the public inputs of every proof that carries
// it, so the equalities the off chain verifier enforces between proofs are
// enforced by construction instead.
//
// The verification key hashes are compiled in, so this circuit's identity
// fixes exactly which variants it aggregates, the way an off chain
// verifier's accepted key list does. The keys themselves stay private
// witnesses; the backend constrains each against its pinned hash.
//
// The backend produces a proof over an unsatisfied witness without
// complaint, so executing and even proving this circuit means nothing on
// its own: a forged inner proof surfaces only when the registration proof
// is verified, and a caller must treat verification as the only outcome.
//
// The extraction is pinned to data group 1, where Doc 9303 puts the machine
// readable zone that the aggregated attribute circuit parses.
//
// Published: domain, context, and the four returned values. The bindings
// that only link the inner proofs to each other, including the signer
// commitment, stay private, so a registration proof exposes less than the
// bundle it replaces.

mod keys;

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};

fn main(
    sod_key: UltraHonkVerificationKey,
    sod_proof: UltraHonkZKProof,
    dg_extract_key: UltraHonkVerificationKey,
    dg_extract_proof: UltraHonkZKProof,
    attributes_key: UltraHonkVerificationKey,
    attributes_proof: UltraHonkZKProof,
    anchor_key: UltraHonkVerificationKey,
    anchor_proof: UltraHonkZKProof,
    econtent_binding: Field,
    dsc_commitment: Field,
    secret_binding: Field,
    dg_binding: Field,
    commitment: Field,
    current_yyyymmdd: Field,
    registry_root: Field,
    domain: pub Field,
    context: pub Field,
) -> pub (Field, Field, Field, Field) {
    assert(domain != 0, "registration: domain must be set");

    assert(context != 0, "registration: context must be set");

    verify_honk_proof(
        sod_key,
        sod_proof,
        [domain, context, econtent_binding, dsc_commitment, secret_binding],
        keys::SOD,
    );

    verify_honk_proof(
        dg_extract_key,
        dg_extract_proof,
        [1, econtent_binding, domain, context, dg_binding],
        keys::DG_EXTRACT,
    );

    verify_honk_proof(
        attributes_key,
        attributes_proof,
        [dg_binding, current_yyyymmdd, domain, context, commitment],
        keys::ATTRIBUTES,
    );

    verify_honk_proof(
        anchor_key,
        anchor_proof,
        [registry_root, domain, context, dsc_commitment],
        keys::ANCHOR,
    );

    (commitment, secret_binding, current_yyyymmdd, registry_root)
}
