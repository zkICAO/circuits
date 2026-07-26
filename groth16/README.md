# Groth16 predicates

The same predicate statements as `bin/predicate/`, proved with Groth16 over circom instead of UltraHonk over Noir, for the case where a verifier is a contract and proof size is what costs.

## Why this lives here and not in its own repository

Every other part of zkICAO is a repository of its own, so a separate one would have been the obvious move. It is the wrong one here for a reason that is specific to this work.

The load bearing property of this directory is that its Poseidon2 is bit for bit the Poseidon2 the Noir circuits use. A predicate that opened a commitment with a different hash would compute a different root and prove nothing about the document, and it would do so silently, since both proofs would verify against their own verification keys. That agreement is checked by taking a commitment and an opening the Noir circuits actually produced and requiring this stack to open it, which needs both stacks present in one checkout.

Splitting them would put that check across two repositories and back into cross repository continuous integration, which is the arrangement this project has already removed once: a check that depends on a credential or on a second checkout does not fail when it lapses, it skips.

The naming follows the same reasoning. Repositories here are named for their role, `circuits`, `prover`, `docs`, `contracts`, not for a technology. `groth16` names a proving system, so it is a directory inside the role it belongs to rather than a repository beside them.

## Layout, which mirrors the Noir tree deliberately

```
poseidon2/    the hash and the derived values of lib/core/commit, ported
bin/predicate/<statement>/   the same phase and instantiation names as bin/predicate/
test/         the agreement vectors and the compiled artifacts
tools/        regenerates the constants from the pinned Barretenberg revision
```

`bin/predicate/compare` here and `bin/predicate/compare` in the Noir tree are the same statement in two proving systems. An auditor reading one can find the other by the same path.

## The agreement, and how it is checked

The constants come from the Poseidon2 parameters of the Barretenberg revision `TOOLCHAIN.md` pins, extracted by `tools/constants.py` rather than transcribed, because a transcription error would be invisible.

Matching constants are a reason to expect agreement, not evidence of it. The evidence is two checks:

The hash agrees at every width the protocol uses. `tools/hash_vectors` in the Noir tree prints Poseidon2 over 2, 3, 4, 5 and 8 elements; `test/vectors.circom` computes the same and the values must be equal. The widths matter individually because the sponge behaves differently at each: an input that divides evenly into three element chunks runs no final permutation, and one that does not runs one.

The whole opening agrees. A commitment and a field opening produced by the Noir attribute circuit are fed to this stack, and the witness must solve. That covers the leaf format, the path walk and the commitment, not only the hash.

Both are run by `test/check.sh`.

## Proving in Rust, without a JavaScript or WebAssembly runtime

`prover/` is the path a holder's device takes. circom emits a graph beside
the circuit, `circom-witnesscalc` walks it in Rust, and the graph is held
once rather than reread per proof. The JavaScript calculator is for
development.

The dependency is pinned by revision, not by version. The graph is a private
format shared between the builder and the calculator, so a graph written by
one revision is not readable by another, and the published 0.2 does not ship
the builder at all. Build the builder from the same revision:

```
cargo install --git https://github.com/iden3/circom-witnesscalc \
  --rev d48eb7c97857d46b8a75c94ab96f769207263245 build-circuit

build-circuit bin/predicate/compare/main.circom build/compare.graph
```

Proving is rapidsnark, over its C interface, behind the `rapidsnark`
feature because the library is not on crates.io and has to be built for the
host. Everything stays in memory: a proving key and a witness are the two
things a holder must not leave on disk, and the interface takes both as
buffers.

```
git clone --recursive https://github.com/iden3/rapidsnark
cd rapidsnark && ./build_gmp.sh macos_arm64 && make macos_arm64
export RAPIDSNARK_LIB=$PWD/package_macos_arm64/lib

cargo test --features rapidsnark
```

One property to know before building on this, and it is the same property
the Noir side records for Barretenberg. Neither the graph walker nor
rapidsnark checks a constraint: an opening that belongs to no commitment
produces a witness, and that witness produces a proof. Verification is what
refuses it, and this is checked rather than asserted, by proving such a
witness and asking snarkjs, which answers `Invalid proof`.

So on both stacks the rule is one rule: a produced proof is not a valid
proof, and only verifying answers the question. An integration that treats
production as validation is wrong in both.

The JavaScript witness calculator does refuse the same input, which is why
it can look as though generating a witness validates it. It does not, on the
path a deployment uses.

One compilation detail matters and is easy to lose. The proving key and the
witness graph must come from the same circom optimization level, because the
witness width depends on it: `tools/setup.sh` passes `--O2` to match what
`build-circuit` applies, and a mismatch surfaces as rapidsnark reporting a
witness that belongs to another circuit.

## Measured

| What | Groth16 here | UltraHonk in the Noir tree |
|---|---:|---:|
| proof, on chain | 256 bytes | 11,072 bytes |
| constraints, compare | 6,456 | 123 ACIR opcodes |
| constraints, member | 11,545 | 230 ACIR opcodes |
| constraints, reveal | 5,613 | 100 ACIR opcodes |

The comparison is not like for like and is not meant to be: the two systems count different things. What it does show is the reason this exists, which is the proof size a contract pays for.

## Setup, and why no proving key is committed

Phase 1 is the Ethereum powers of tau ceremony, downloaded rather than generated. `tools/setup.sh` fetches it and verifies it with snarkjs before use.

Phase 2 is per circuit, and its output is a proving key that this repository does not and must not carry. A Groth16 phase 2 has toxic waste: whoever holds the entropy of a contribution can forge proofs for that circuit. A key produced by a single local contribution is fine to develop against and unfit for anything else, so `build/` is ignored and every artifact in it is rebuilt.

A deployment runs its own phase 2 with as many independent contributors as it wants to be able to claim, and publishes the transcript. That is the deployment's ceremony, not this project's, for the same reason the trust registry is the relying party's: a project that ran the ceremony for everyone would be a party everyone has to trust.

This is the one place where the two proving systems differ in what a relying party must arrange. UltraHonk needs no per circuit ceremony at all, so a deployment that does not want to run one has that option and pays for it in proof size.
