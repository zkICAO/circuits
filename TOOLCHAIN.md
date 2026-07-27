# Toolchain lock

Do not upgrade any of these mid phase. Upgrades happen as a dedicated task with the full workspace recompiled and all tests re-run.

## Compilers and provers

| Component | Version | Note |
|---|---|---|
| nargo | 1.0.0-beta.19 | `noirup -v 1.0.0-beta.19` |
| Barretenberg (bb) | 4.2.0-aztecnr-rc.2 | proves and verifies the bundle; write_vk pins the registration key hashes |

## Noir dependencies

Pinned in the packages that use them. Tags below are the versions currently resolved by the workspace.

| Crate | Tag | Source | Used by |
|---|---|---|---|
| sha256 | v0.3.0 | noir-lang/sha256 | hash |
| poseidon | v0.2.6 | noir-lang/poseidon | commit |
| bignum | v0.9.2-1 | zkpassport/noir-bignum | rsa, sig |
| bigcurve | v0.13.2-1 | zkpassport/noir_bigcurve | sig |
| ecdsa | v0.3.0 | zkpassport/noir-ecdsa | sig |
| bb_proof_verification | v4.2.0-aztecnr-rc.2 | AztecProtocol/aztec-packages, directory barretenberg/noir/bb_proof_verification | registration |

RSA PKCS#1 v1.5 is implemented in `lib/rsa` on the bignum modexp, with no dependency of its own. Active Authentication for RSA keys would need ISO 9796-2 with SHA-1, neither of which is carried; the elliptic curve variant in `bin/chip` needs nothing beyond the pins above.

## Groth16 stack

The second proving stack under `groth16/` has its own pins, recorded in `groth16/README.md` alongside the commands that use them.

| Component | Version | Note |
|---|---|---|
| circom | v2.2.3 | `cargo install --locked --git https://github.com/iden3/circom.git --tag v2.2.3 circom` |
| snarkjs | 0.7.5 | setup, key export and the reference verifier |
| circom-witnesscalc | rev d48eb7c97857d46b8a75c94ab96f769207263245 | both the `build-circuit` binary and the library dependency, pinned to the same revision so the graph format matches |
| rapidsnark | built from source | C interface behind the `rapidsnark` cargo feature of `groth16/prover` |

## Checking the pin

Every circuit in the workspace compiles against every dependency above, so a clean `nargo compile` is itself the check that the graph resolves under the pin. A separate build probe existed for this and was removed once the real circuits covered it.
