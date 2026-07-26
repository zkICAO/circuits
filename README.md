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

A registration circuit verifies the anchor, sod, dg-extract and attributes proofs recursively and publishes their linked outputs, so a relying party can take one proof where the equalities hold by construction instead of four proofs and a checklist. Two variants exist: one over the signer registry, one that walks the chain to the country signing key with its validity date tied to the attribute date by a shared witness. The inner verification key hashes are compiled in, from a generated `keys.nr` written by `cargo run -- keys`. The predicates and the nullifier stay separate, because a document registers once and gets asked questions per session; a session that asks more than one question aggregates its predicates the same way, `session/compare_member` being the first pair. One property of the backend matters when integrating: producing a proof does not check the witness, so a registration proof over a forged inner proof is produced without complaint and rejected when verified. Verification is the only outcome that means anything.

Doc 9303 makes DG1 (the machine readable zone) mandatory on every compliant document, so profiles that read DG1 are what keep the core portable across issuing states. Data groups an individual state defines, such as DG13, are opt-in enrichment and are not implemented.

## Circuits

Measured with `nargo info`, ACIR opcodes:

| Circuit | Opcodes | What it proves |
|---|---:|---|
| `sod/ecdsa_p256_sha256_ec1024` | 38034 | the signer signed the Security Object, ECDSA over P-256 |
| `sod/ecdsa_p256_sha256_ec512` | 35098 | the same, for a smaller Security Object |
| `sod/rsa2048_v15_sha256_ec1024` | 11036 | the same, RSA-2048 with PKCS#1 v1.5 |
| `sod/rsa2048_v15_sha256_ec512` | 8100 | the same, for a smaller Security Object |
| `anchor/csca_chain_rsa2048_sha256_tbs512` | 6841 | a country signing key certified the signer, checked in circuit |
| `dg_extract/sha256_ec1024` | 6237 | a data group hash the Security Object commits to |
| `dg_extract/sha256_ec512` | 3301 | the same, for a smaller Security Object |
| `attributes/mrz_td1_sha256` | 2449 | the fields of a card machine readable zone |
| `attributes/mrz_td3_sha256` | 2103 | the fields of a passport machine readable zone |
| `anchor/dsc_inclusion` | 340 | the signer key is in a published set |
| `predicate/member` | 230 | a field is one of a published set |
| `predicate/compare` | 123 | a field is within a range |
| `predicate/reveal` | 100 | a field, disclosed verbatim |
| `nullifier/document_number` | 58 | scoped uniqueness for one document |
| `registration/mrz_td3_ecdsa_p256_sha256_ec512_inclusion` | 17 | the four document proofs, verified recursively as one |
| `registration/mrz_td3_ecdsa_p256_sha256_ec512_csca_chain` | 17 | the same, with the country signing chain checked in circuit |
| `session/compare_member` | 9 | two predicates of a session, verified recursively as one |

The Security Object signature dominates and runs once. Everything a verifier actually asks about costs two or three orders of magnitude less, which is why the signature check and the data group extraction are separate circuits rather than one.

RSA is cheaper than the elliptic curve here, which is worth stating because it inverts the usual expectation: verifying RSA with a small exponent is seventeen modular multiplications, while an ECDSA verification is two scalar multiplications over a curve whose field is not the proving field, so it pays for non native arithmetic throughout.

## Layout

```
lib/core/     commit hash sig rsa x509 normalize          no ICAO knowledge
lib/emrtd/    cms lds sod dg_extract mrz attributes       Doc 9303 chip documents
lib/trust/    anchor                                       the ICAO certificate chain
lib/claims/   predicate nullifier policy                   statements about a commitment
lib/testdata/                                              generated fixtures

bin/<phase>/<instantiation>/    one package per compiled circuit
tools/                          executed to solve a witness, never proved: openings,
                                leaves, and the trees a verifier publishes
fixtures/generator/             builds the documents the tests run against
```

The project is named for ICAO rather than for one of its documents, and the grouping is where that shows. Doc 9303 is the first standard implemented and `lib/emrtd` is the part specific to it. A second ICAO credential family, a visible digital seal for instance, would add a sibling of `emrtd` and reuse `core`, `trust` and `claims` unchanged: a commitment, a certificate chain and a predicate do not care which document they came from.

The rule that keeps this true is that `core` holds no knowledge of any standard. It packs bytes, hashes, verifies signatures and reads certificate fields; it does not know what a data group is, what a machine readable zone contains, or which country codes exist. Where a comment there names Doc 9303, it names it as the first instance of a general rule, never as the definition. `claims` is the same at the other end: a predicate opens a committed field and a nullifier scopes an identifier, and neither knows which standard produced the commitment.

## Naming

A circuit is `bin/<phase>/<instantiation>`, and its package is `<phase>_<instantiation>`, which is also the name the verifier knows it by.

`<phase>` is the mechanism in the standard. `<instantiation>` is whatever makes two builds of that phase different, and that axis is not the same for every phase, because what varies is not the same:

| phase | what differs | example |
|---|---|---|
| `sod` | signature, digest, buffer | `ecdsa_p256_sha256_ec512` |
| `dg_extract` | digest, buffer | `sha256_ec512` |
| `attributes` | profile, digest | `mrz_td3_sha256` |
| `anchor` | mode, then algorithm | `dsc_inclusion`, `csca_chain_rsa2048_sha256_tbs512` |
| `predicate` | the statement | `compare` |
| `nullifier` | the policy | `document_number` |
| `registration` | the aggregated variant set | `mrz_td3_ecdsa_p256_sha256_ec512_inclusion` |
| `session` | the aggregated question pair | `compare_member` |

Underscores rather than hyphens throughout: Nargo rejects a package name containing a hyphen.

A circuit pays for its buffer, not for the actual document length, which is why sizes are instantiations rather than one large buffer.

## Choosing a buffer

A Security Object holds one entry per data group, 39 bytes each with SHA-256 hashes. Twelve data groups fit 512 bytes and thirteen do not, and Doc 9303 allows sixteen, so a document carrying more than twelve needs the 1024 byte variant. Larger digests move the line further: with SHA-512 entries only six fit 512 bytes.

Doubling the buffer costs 2936 ACIR opcodes in every variant, which is the extra hashing and nothing else. Against the 35098 of an elliptic curve signature check that is eight percent; against a data group extraction it is most of the circuit.

## The trees a verifier publishes

Three trees carry the values a verifier decides for itself: a signer registry at depth sixteen, a master list at depth ten, and a membership set at depth eight. It builds them with the tools rather than reimplementing the hashing, and publishes only the roots.

A tree of a few hundred entries at depth sixteen is mostly empty, so padding is part of the format: an absent leaf is zero and every level above is that level's empty root paired with itself. It is a convention rather than a caller's choice, because a published root and a circuit walking a path to it are comparable only if both padded the same way. `tools/merkle_path` implements it, tested at every index at all three depths against the same path walk the circuits use.

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
- Deployment and audit: the reference on chain registry in [zkICAO/contracts](https://github.com/zkICAO/contracts) verifies real proofs under test and is deployed nowhere
- Session question compositions beyond the compare and member pair, and any on chain session questions
- Nullifier policies that survive document reissue, which need a secret that is not chip bound

## What is fixed and what is yours

zkICAO is infrastructure, so the boundary matters. Fixed by the protocol: the hash tags and derived value formats in `lib/core/commit`, the policy identifiers, the tree depths, the public input layouts. Functions of the toolchain, regenerated rather than configured: every verification key, the `keys.nr` hashes the recursive circuits compile in (`cargo run -- keys`), and the Solidity verifiers (`bb write_solidity_verifier`); never edit these by hand. Chosen by each application: its `domain`, its accepted verification keys, its one nullifier policy, the registry or master list it trusts as a root it builds itself, its date window, a fresh `context` per exchange. Kept by the holder and never sent: the session salt behind a registered commitment, the DSC salt, the document secret. No repository commits private key material; every fixture document is synthetic.

## Toolchain

Pinned versions and dependency tags: see [TOOLCHAIN.md](TOOLCHAIN.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report a vulnerability privately: [SECURITY.md](SECURITY.md).

## Trademarks

See [TRADEMARKS.md](TRADEMARKS.md).

## License

MIT
