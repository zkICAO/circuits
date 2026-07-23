# Toolchain lock

Do not upgrade any of these mid phase. Upgrades happen as a dedicated task with the full workspace recompiled and all tests re-run.

## Compilers and provers

| Component | Version | Note |
|---|---|---|
| nargo | 1.0.0-beta.19 | `noirup -v 1.0.0-beta.19` |
| Barretenberg (bb) | 4.2.0-aztecnr-rc.2 | native FFI used by the prover repo |
| noir_rs (prover repo) | v1.0.0-beta.19-4 | zkpassport/noir_rs, matches nargo pin |

## Noir dependencies (known good set for beta.19)

| Crate | Tag | Source |
|---|---|---|
| sha256 | v0.3.0 | noir-lang/sha256 |
| sha1 | v0.11 | zac-williamson/sha1 |
| poseidon | v0.2.6 | noir-lang/poseidon |
| bignum | v0.9.2-1 | zkpassport/noir-bignum |
| bigcurve | v0.13.2-1 | zkpassport/noir_bigcurve |
| ecdsa | v0.3.0 | zkpassport/noir-ecdsa |

RSA (PKCS#1 v1.5, e = 65537) is implemented directly on bignum modexp; no extra dependency. This path is already proven in production style use (ISO 9796-2 RSA 2048 signature recovery on real documents with the same bignum version).

## Probe

`probe/` is a minimal circuit that imports and exercises every dependency above. If `nargo compile` succeeds on the workspace, the dependency graph resolves and type checks under the pin. CI runs it on every push.
