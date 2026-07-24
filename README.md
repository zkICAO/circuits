# zkICAO circuits

Noir circuits for privacy preserving verification of electronic identity documents, proved with UltraHonk (Barretenberg).

The first target is ICAO Doc 9303 (Machine Readable Travel Documents): ePassports and national eID cards that carry a contactless chip. Other ICAO specifications are out of scope for now and will be considered on their own merits rather than assumed to fit.

Status: early development. Only the shared libraries exist so far. No circuit implements the protocol yet, nothing has been proved end to end, and every name, layout and binding format below can still change.

## Intended design

Small composable circuits linked by shared public values, rather than one monolithic prover, so that a verifier checks each proof and a fixed set of equalities between their public values.

```
anchor/dsc-inclusion | anchor/csca-chain   (optional) DSC trust, up to the CSCA
sod                                        document signer signature over the Security Object
  dg-extract                               a data group hash committed by that Security Object
    attributes/<profile>                   parse one data group, commit its fields
      predicate/compare                    numeric checks (age, expiry, ranges)
      predicate/member                     set membership (nationality, issuing state)
      predicate/reveal                     disclose a single field
      nullifier                            scoped uniqueness, versioned policies
credential                                 (optional, on chain) recursive aggregation
```

Doc 9303 makes DG1 (the machine readable zone) mandatory on every compliant document, so profiles that read DG1 are what keep the core portable across issuing states. Data groups defined by an individual state, such as DG13, are opt-in enrichment on top.

Binding values, leaf formats and salt conventions are specified in [zkICAO/docs](https://github.com/zkICAO/docs) and implemented here once, in `lib/commit`; no circuit re-derives them. Circuits are intended to carry two scoping public inputs, `domain` (per application identity scoping) and `context` (per session freshness), once they exist.

## Layout

```
lib/tlv         DER tag and definite length decoding
lib/lds         Security Object helpers: hash algorithm identifier, data group entries
lib/hash        message digests
lib/mrz         TD1 and TD3 field offsets, check digits, two digit year resolution
lib/normalize   raw field bytes into canonical values
lib/commit      binding values, leaf format, Merkle tree, salt conventions
lib/policy      nullifier policy identifiers
lib/sig         signature verification wrappers
probe/          build canary that imports every pinned dependency
```

Doc 9303 also defines the TD2 layout, which `lib/mrz` does not implement yet.

## Toolchain

Pinned versions and dependency tags: see [TOOLCHAIN.md](TOOLCHAIN.md).

## Trademarks

See [TRADEMARKS.md](TRADEMARKS.md).

## License

MIT
