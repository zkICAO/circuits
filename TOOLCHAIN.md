# Toolchain lock

Do not upgrade any of these mid phase. Upgrades happen as a dedicated task with the full workspace recompiled and all tests re-run.

## Compilers and provers

| Component | Version | Note |
|---|---|---|
| nargo | 1.0.0-beta.19 | `noirup -v 1.0.0-beta.19` |
| Barretenberg (bb) | 4.2.0-aztecnr-rc.2 | intended for the prover repository; not exercised here yet |
| noir_rs | v1.0.0-beta.19-4 | intended for the prover repository; not exercised here yet |

## Noir dependencies

Pinned in the packages that use them. Tags below are the versions currently resolved by the workspace.

| Crate | Tag | Source | Used by |
|---|---|---|---|
| sha256 | v0.3.0 | noir-lang/sha256 | hash, probe |
| poseidon | v0.2.6 | noir-lang/poseidon | commit, probe |
| bignum | v0.9.2-1 | zkpassport/noir-bignum | sig, probe |
| bigcurve | v0.13.2-1 | zkpassport/noir_bigcurve | sig, probe |
| ecdsa | v0.3.0 | zkpassport/noir-ecdsa | sig, probe |
| sha1 | v0.11 | zac-williamson/sha1 | probe |

RSA is not implemented. Documents whose Document Signer Certificate uses RSA are therefore not yet supported; adding that path is tracked work, and this table is the place to record the dependency it lands with.

## Probe

`probe/` is a minimal circuit that imports and exercises every dependency above. If `nargo compile` succeeds on the workspace, the dependency graph resolves and type checks under the pin. It is a build canary only: it verifies nothing about the protocol and is not part of any proving flow.
