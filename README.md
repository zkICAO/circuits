# zkICAO circuits

Noir circuits for privacy preserving verification of electronic identity documents, proved with UltraHonk (Barretenberg).

The first target is ICAO Doc 9303 (Machine Readable Travel Documents): ePassports and national eID cards that carry a contactless chip. Other ICAO specifications are out of scope for now and will be considered on their own merits rather than assumed to fit.

Status: early development. The chain below runs end to end against generated documents, and a proof over one of them verifies. Names, layouts and binding formats can still change, and the coverage gaps at the bottom of this page are real.

## The chain

```
anchor/dsc-inclusion | anchor/csca-chain   (optional) is the signer one we trust
sod                                        did the signer sign this document
  dg-extract                               which data group hash did it commit to
    attributes/<profile>                   parse that data group, commit its fields
      predicate/compare                    numeric checks (age, expiry, ranges)
      predicate/member                     set membership (nationality, issuing state)
      predicate/reveal                     disclose a single field
      nullifier                            scoped uniqueness, versioned policies
```

Proofs are linked by equalities between their public values, not by trust in any one of them. The off-chain verifier in [zkICAO/prover](https://github.com/zkICAO/prover) enforces that checklist so an integration does not carry its own copy.

Doc 9303 makes DG1 (the machine readable zone) mandatory on every compliant document, so profiles that read DG1 are what keep the core portable across issuing states. Data groups an individual state defines, such as DG13, are opt-in enrichment and are not implemented.

## Circuits

Measured with `nargo info`, ACIR opcodes:

| Circuit | Opcodes | What it proves |
|---|---:|---|
| `sod/ecdsa_p256_sha256_ec512` | 35098 | the signer signed the Security Object, ECDSA over P-256 |
| `sod/rsa2048_v15_sha256_ec512` | 8100 | the same, RSA-2048 with PKCS#1 v1.5 |
| `anchor/csca_chain_rsa2048_sha256_tbs512` | 6841 | a country signing key certified the signer, checked in circuit |
| `dg_extract/sha256_ec512` | 3301 | a data group hash the Security Object commits to |
| `attributes/mrz_td1_sha256` | 2449 | the fields of a card machine readable zone |
| `attributes/mrz_td3_sha256` | 2103 | the fields of a passport machine readable zone |
| `anchor/dsc_inclusion` | 340 | the signer key is in a published set |
| `predicate/member` | 230 | a field is one of a published set |
| `predicate/compare` | 123 | a field is within a range |
| `predicate/reveal` | 100 | a field, disclosed verbatim |
| `nullifier/document_number` | 58 | scoped uniqueness for one document |

The Security Object signature dominates and runs once. Everything a verifier actually asks about costs two or three orders of magnitude less, which is why the signature check and the data group extraction are separate circuits rather than one.

RSA is cheaper than the elliptic curve here, which is worth stating because it inverts the usual expectation: verifying RSA with a small exponent is seventeen modular multiplications, while an ECDSA verification is two scalar multiplications over a curve whose field is not the proving field, so it pays for non native arithmetic throughout.

## Layout

```
lib/            shared libraries, where the logic lives
bin/<name>/<variant>/   one package per compiled variant, a thin instantiation
fixtures/generator/     builds the synthetic documents the tests run against
tools/          execution only helpers, never proved
```

Variants differ by signature algorithm, digest algorithm and buffer size. A circuit pays for its buffer, not for the actual document length, which is why sizes are variants rather than one large buffer.

## Fixtures

`fixtures/generator` builds complete Doc 9303 material: DG1 wrapping a specimen machine readable zone, a Security Object over DG1 and DG2, CMS signed attributes, an ECDSA or RSA signature, and a Document Signer certificate signed by a country signing key. It has no external crates: DER is emitted directly, openssl handles key generation and signing, and a small big integer implementation computes the Barrett reduction parameter the bignum backend takes.

Regenerating produces fresh keys, so the committed output in `lib/testdata` is the fixture of record.

## Verifying a bundle

`cargo run -- bundle` in `fixtures/generator` signs a document, executes every circuit in chain order feeding each one's outputs into the next, and produces and verifies a proof for each. That is the check that the pieces fit; the unit tests exercise circuits in isolation.

The off-chain verifier consumes the result. It returns what a bundle proved, not only that it verified, because the prover chooses the field, the range and the set, and a verifier that learns only "the checks passed" does not know its question was the one answered.

## Not implemented

- Chip authentication of any kind, so a cloned chip carrying genuine data is not detected
- TD2, which Doc 9303 defines alongside TD1 and TD3
- Digest algorithms other than SHA-256, and signature algorithms beyond the variants listed above
- Recursive aggregation, which on-chain verification would need
- Nullifier policies that survive document reissue, which need a secret that is not chip bound

## Toolchain

Pinned versions and dependency tags: see [TOOLCHAIN.md](TOOLCHAIN.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report a vulnerability privately: [SECURITY.md](SECURITY.md).

## Trademarks

See [TRADEMARKS.md](TRADEMARKS.md).

## License

MIT
