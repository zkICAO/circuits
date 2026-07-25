//! Produces the value an application stores to recognise a repeat
//! registration, under the document number policy.
//!
//! Two public inputs tie it to the rest of the chain: the commitment the
//! attribute circuit published, which is where the fields come from, and the
//! secret binding the Passive Authentication circuit published, which is
//! what the prover must hold the secret for.

fn main(
    state_length: u32,
    state_data: [Field; 4],
    state_entropy: Field,
    state_siblings: [Field; 4],
    number_length: u32,
    number_data: [Field; 4],
    number_entropy: Field,
    number_siblings: [Field; 4],
    secret: Field,
    commitment: pub Field,
    secret_binding: pub Field,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(context != 0, "nullifier: context must be set");

    assert(domain != 0, "nullifier: domain must be set");

    nullifier::document_number(
        predicate::FieldOpening {
            field_id: 2,
            length: state_length,
            data: state_data,
            entropy: state_entropy,
            siblings: state_siblings,
        },
        predicate::FieldOpening {
            field_id: 3,
            length: number_length,
            data: number_data,
            entropy: number_entropy,
            siblings: number_siblings,
        },
        commitment,
        secret,
        secret_binding,
        domain,
    )
}

fn sample(domain: Field) -> ([Field; 4], [Field; 4], Field) {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..16 {
        let data: [Field; 4] = if i == 1 {
            [0x55544f, 0, 0, 0]
        } else if i == 2 {
            [0x4c383938393032433336, 0, 0, 0]
        } else {
            [0, 0, 0, 0]
        };

        let length: Field = if i == 1 {
            3
        } else if i == 2 {
            9
        } else {
            0
        };

        leaves[i] = commit::leaf((i as Field) + 1, length, data, (i as Field) + 1000);
    }

    let mut level8: [Field; 8] = [0; 8];

    for i in 0..8 {
        level8[i] = commit::hash_pair(leaves[2 * i], leaves[2 * i + 1]);
    }

    let mut level4: [Field; 4] = [0; 4];

    for i in 0..4 {
        level4[i] = commit::hash_pair(level8[2 * i], level8[2 * i + 1]);
    }

    let mut level2: [Field; 2] = [0; 2];

    for i in 0..2 {
        level2[i] = commit::hash_pair(level4[2 * i], level4[2 * i + 1]);
    }

    let state_siblings: [Field; 4] = [leaves[0], level8[1], level4[1], level2[1]];

    let number_siblings: [Field; 4] = [leaves[3], level8[0], level4[1], level2[1]];

    (state_siblings, number_siblings, commit::commitment(commit::root16(leaves), domain))
}

#[test]
fn produces_a_stable_value_for_one_application() {
    let domain = 42;

    let secret = 123456;

    let (state_siblings, number_siblings, commitment) = sample(domain);

    let binding = commit::secret_binding(secret, domain);

    let value = main(
        3,
        [0x55544f, 0, 0, 0],
        1001,
        state_siblings,
        9,
        [0x4c383938393032433336, 0, 0, 0],
        1002,
        number_siblings,
        secret,
        commitment,
        binding,
        domain,
        7,
    );

    assert(value != 0);
}

#[test(should_fail_with = "nullifier: secret does not match the authenticated document")]
fn rejects_a_secret_the_prover_invented() {
    let domain = 42;

    let (state_siblings, number_siblings, commitment) = sample(domain);

    let binding = commit::secret_binding(123456, domain);

    let _ = main(
        3,
        [0x55544f, 0, 0, 0],
        1001,
        state_siblings,
        9,
        [0x4c383938393032433336, 0, 0, 0],
        1002,
        number_siblings,
        999999,
        commitment,
        binding,
        domain,
        7,
    );
}
