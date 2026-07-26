# Toolchain lock

Do not upgrade any of these mid phase. Upgrades happen as a dedicated task with the full workspace recompiled and all tests re-run.

## Compilers and provers

| Component | Version | Note |
|---|---|---|
| nargo | 1.0.0-beta.19 | `noirup -v 1.0.0-beta.19` |
| Barretenberg (bb) | 4.2.0-aztecnr-rc.2 | proves and verifies the bundle; write_vk pins the registration key hashes |
| noir_rs | v1.0.0-beta.19-4 | intended for the prover repository; not exercised here yet |

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

RSA PKCS#1 v1.5 is implemented in `lib/rsa` on the bignum modexp, with no dependency of its own. SHA-1 was pinned for an Active Authentication path that is not implemented; the dependency went when the build probe that was its only user did.

## Checking the pin

The eleven circuits compile against every dependency above, so a clean `nargo compile` on the workspace is itself the check that the graph resolves under the pin. A separate build probe existed for this and was removed once the real circuits covered it.
