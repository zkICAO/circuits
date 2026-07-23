//! Toolchain lock probe. Exercises every pinned dependency so `nargo compile`
//! validates the whole dependency graph under TOOLCHAIN.md. Never executed.

use bigcurve::curves::brainpoolP384r1::{BrainpoolP384r1_Fq, BrainpoolP384r1_Fr};

use bignum::BigNum;

use ecdsa::ecdsa::verify_brainpoolp384r1_ecdsa;

use poseidon::poseidon2::Poseidon2;

use sha1::sha1::digest as sha1_digest;

use sha256::sha256_var;

fn main(
    msg: [u8; 64],
    msgLen: u32,
    pubkeyX: [u8; 48],
    pubkeyY: [u8; 48],
    signatureR: [u8; 48],
    signatureS: [u8; 48],
    seed: pub Field,
) -> pub Field {
    let h256 = sha256_var(msg, msgLen);

    let h1 = sha1_digest(msg);

    let pkX: BrainpoolP384r1_Fq = BrainpoolP384r1_Fq::from_be_bytes(pubkeyX);

    let pkY: BrainpoolP384r1_Fq = BrainpoolP384r1_Fq::from_be_bytes(pubkeyY);

    let sigR: BrainpoolP384r1_Fr = BrainpoolP384r1_Fr::from_be_bytes(signatureR);

    let sigS: BrainpoolP384r1_Fr = BrainpoolP384r1_Fr::from_be_bytes(signatureS);

    let ok = verify_brainpoolp384r1_ecdsa(pkX, pkY, h256, (sigR, sigS));

    Poseidon2::hash([seed, h256[0] as Field, h1[0] as Field, ok as Field], 4)
}
