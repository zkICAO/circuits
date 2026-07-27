# Contributing

## What the project needs

The gaps are listed at the bottom of the README and in `threat-model.md` in the [docs repository](https://github.com/zkICAO/docs). The ones where help goes furthest:

- Test vectors from real documents. Everything here runs against synthetic documents the fixture generator builds, so a genuine Security Object from any issuing state, with personal data removed, is worth more than most code contributions. Say which state and which layout it came from.
- Algorithm coverage. Digest algorithms other than SHA-256, and signature variants beyond those in the README.
- Anything in the threat model marked as not protected against.

## What a change needs to carry

**A test that fails without it.** For a circuit that means a `#[test]` that the change makes pass, and for a security fix it means a test that demonstrates the problem first. Several fixes in the history were made this way and the commit says so.

**Measured numbers, never estimated ones.** If a change affects circuit size, run `nargo info` and put the real figure in the commit message. Opcode counts live in one table in `architecture.md`; update it rather than quoting a number somewhere else.

**Honest limits.** If a change works for one case and not another, the documentation says which. Overstating what something does is treated as a defect here, and the review passes over this repository have caught more of those than logic errors.

## Running things

```
nargo test                                              # all circuits and libraries
nargo info                                              # circuit sizes
cd fixtures/generator && cargo run -- bundle            # prove a document end to end
cd fixtures/generator && cargo run -- bundle --no-prove # check the chain, no backend needed
cd fixtures/generator && cargo run                      # regenerate the committed fixtures
```

Regenerating fixtures produces fresh keys, so every value derived from a key changes and the committed output in `lib/testdata` is what the tests run against. Run `nargo test` after regenerating.

The off-chain verifier lives in [zkICAO/prover](https://github.com/zkICAO/prover). Its integration tests read a bundle built here; point `ZKICAO_BUNDLE` at `target/bundle`.

## Style

`nargo fmt` and `cargo fmt` decide formatting; CI checks both, and `cargo clippy` runs with warnings denied.

Comments explain why, not what. A comment that restates the line above it will be removed in review.

No em-dashes or en-dashes in anything published: commit messages, documentation, code comments. Plain punctuation instead.

Commits follow conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`) and the body says what changed and why, not what the diff already shows.

## Changing a shared value

Binding values, leaf formats, salt conventions and nullifier policies are specified in the docs repository and implemented once in `lib/core/commit`. Changing one means publishing the revised specification first, then updating the implementation against it. A change that lands here first has no reference to review against.

Public input order is a contract with the verifier. If you change a circuit signature, regenerate `layout.manifest` in the prover repository; its tests fail otherwise, which is the point.
