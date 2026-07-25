# Security

## Reporting

Report a suspected vulnerability privately, through GitHub's private vulnerability reporting on this repository. Please do not open a public issue for one.

Include what you need to make the case: the file and function, what an attacker gains, and the steps or the witness that demonstrate it. A proof of concept is welcome but not required if the argument is clear from the code.

Expect an acknowledgement within a week. If a report is valid you will be credited in the fix unless you ask otherwise.

## What is in scope

Anything that lets a prover establish something false, or a verifier learn something it should not:

- A witness that satisfies a circuit while contradicting what the circuit is documented to prove
- Two distinct inputs producing the same binding value, commitment or nullifier
- A public value that reveals more about a holder than the specification says it does
- A bundle that passes the off-chain checklist while its proofs describe different documents
- Anything in the fixture generator that could reach a user's filesystem or keys

## What is already known

These are documented rather than reported. `threat-model.md` in the [docs repository](https://github.com/zkICAO/docs) is the full list; the ones most often mistaken for bugs are:

- Chip authentication is not implemented, so a cloned chip carrying genuine data is indistinguishable from the original
- Without an anchor proof, a bundle establishes that some key signed the document and nothing about whose key it is
- A nullifier built on the document signature does not survive document reissue, and nothing deduplicates a holder across two different documents
- The date a proof resolves two digit years against is a public input; a verifier that does not pin it accepts whatever the prover chose

## Status

Nothing here has been audited. The circuits, the libraries and the verifier have been reviewed by their authors and by adversarial review passes over the code, which found real defects and are recorded in the commit history, but that is not an audit and should not be read as one.

This is not production software. Do not use it to make decisions about real people.
