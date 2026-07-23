# zkICAO circuits

Noir circuits for privacy preserving verification of ICAO 9303 electronic identity documents: ePassports (TD3) and national eID cards (TD1), for any issuing state. Proving with UltraHonk (Barretenberg).

Status: early development (P0 bootstrap, P1 in progress). Circuit names, layouts and binding formats are not stable yet.

## Design

Small composable circuits linked by shared public values, instead of one monolithic prover. A verifier checks each proof and a fixed set of equalities between their public values.

```
anchor/dsc-inclusion | anchor/csca-chain   (optional) DSC trust, up to the CSCA
sod                                        document signer signature over the SOD
  dg-extract                               a data group hash committed by that SOD
    attributes/<profile>                   parse one data group, commit its fields
      predicate/compare                    numeric checks (age, expiry, ranges)
      predicate/member                     set membership (nationality, issuing state)
      predicate/reveal                     disclose a single field
      nullifier                            scoped uniqueness, versioned policies
credential                                 (optional, on chain) recursive aggregation
```

Profiles keep the core universal: `mrz-td3` and `mrz-td1` cover every ICAO 9303 document through DG1 (MRZ); country specific data groups (for example `dg13-vn`) are opt-in enrichment.

Binding values, leaf formats and salt conventions are specified once in the docs repository and implemented once in `lib/commit`. Every circuit carries two scoping public inputs: `domain` (per application identity scoping) and `context` (per session freshness).

## Layout

```
lib/     shared libraries: tlv, lds, x509, hash, sig, mrz, normalize, commit, policy
bin/     circuit variants, one Nargo package per variant (sig x hash x buffer size)
probe/   toolchain lock: minimal circuit exercising every pinned dependency
```

## Toolchain

Pinned versions and dependency tags: see [TOOLCHAIN.md](TOOLCHAIN.md).

## License

MIT
