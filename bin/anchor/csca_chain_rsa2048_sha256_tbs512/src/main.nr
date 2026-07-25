//! Proves the Document Signer was certified by a country signing authority
//! the verifier trusts, checking that authority's signature in circuit.
//!
//! The inclusion mode assumes somebody checked the certificates behind the
//! published set. This mode does not: the signature over the certificate is
//! checked here, and only the list of country signing keys stays trusted,
//! which is the anchor of the whole system and cannot be derived from a
//! document.
//!
//! Depth ten holds 1024 country signing keys. The ICAO master list carried
//! 572 certificates when this was written, so depth eight, which holds 256,
//! would not have fitted the real list.

fn main(
    tbs: [u8; 512],
    tbs_len: u32,
    public_key_offset: u32,
    not_before_offset: u32,
    not_after_offset: u32,
    authority_modulus: [u128; 18],
    authority_redc: [u128; 18],
    authority_signature: [u128; 18],
    authority_index: u32,
    authority_siblings: [Field; 10],
    salt: Field,
    master_list_root: pub Field,
    current_yyyymmdd: pub u32,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(context != 0, "anchor: context must be set");

    assert(domain != 0, "anchor: domain must be set");

    anchor::prove_signer_is_certified::<512, 18, 2048, 10>(
        tbs,
        tbs_len,
        public_key_offset,
        not_before_offset,
        not_after_offset,
        authority_modulus,
        authority_redc,
        authority_signature,
        authority_index,
        authority_siblings,
        master_list_root,
        current_yyyymmdd,
        salt,
    )
}

fn master_list() -> ([Field; 10], Field) {
    let mut siblings: [Field; 10] = [0; 10];

    let mut current = commit::modulus_hash(testdata::CHAIN_CSCA_MODULUS_LIMBS);

    for level in 0..10 {
        siblings[level] = (level as Field) + 900;

        current = commit::hash_pair(current, siblings[level]);
    }

    (siblings, current)
}

#[test]
fn certifies_the_document_signer() {
    let (siblings, root) = master_list();

    let commitment = main(
        testdata::CHAIN_TBS,
        testdata::CHAIN_TBS_LEN,
        testdata::CHAIN_PUBLIC_KEY_OFFSET,
        testdata::CHAIN_NOT_BEFORE_OFFSET,
        testdata::CHAIN_NOT_AFTER_OFFSET,
        testdata::CHAIN_CSCA_MODULUS_LIMBS,
        testdata::CHAIN_CSCA_REDC_LIMBS,
        testdata::CHAIN_CSCA_SIGNATURE_LIMBS,
        0,
        siblings,
        3,
        root,
        20260725,
        42,
        7,
    );

    assert(
        commitment
            == commit::dsc_commitment(
                commit::pubkey_hash(testdata::CHAIN_DSC_PUBKEY_X, testdata::CHAIN_DSC_PUBKEY_Y),
                3,
            ),
    );
}

#[test(should_fail_with = "anchor: context must be set")]
fn rejects_an_unset_context() {
    let (siblings, root) = master_list();

    let _ = main(
        testdata::CHAIN_TBS,
        testdata::CHAIN_TBS_LEN,
        testdata::CHAIN_PUBLIC_KEY_OFFSET,
        testdata::CHAIN_NOT_BEFORE_OFFSET,
        testdata::CHAIN_NOT_AFTER_OFFSET,
        testdata::CHAIN_CSCA_MODULUS_LIMBS,
        testdata::CHAIN_CSCA_REDC_LIMBS,
        testdata::CHAIN_CSCA_SIGNATURE_LIMBS,
        0,
        siblings,
        3,
        root,
        20260725,
        42,
        0,
    );
}
