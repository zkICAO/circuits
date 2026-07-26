// The registration that walks the whole chain: the country signing key
// certified the signer, checked in circuit rather than assumed of a curated
// registry. Everything the inclusion variant records holds here too; the
// differences are the anchor slot and one deliberate sharing.
//
// The chain anchor validates the signer certificate at a date, and the
// attribute circuit resolves two digit years at a date. Here they are the
// same witness, placed into both public input arrays, so a prover cannot
// resolve a birth year against one day and certificate validity against
// another. Off chain that equality is a checklist rule; in this circuit it
// cannot be otherwise.
//
// Published: domain, context, and the returned commitment, secret binding,
// date and master list root, the same six field layout as the inclusion
// variant, so a verifier tells the two apart only by verification key.

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
    master_list_root: Field,
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
        [master_list_root, current_yyyymmdd, domain, context, dsc_commitment],
        keys::ANCHOR,
    );

    (commitment, secret_binding, current_yyyymmdd, master_list_root)
}
