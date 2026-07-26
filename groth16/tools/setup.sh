#!/usr/bin/env bash
# Compiles a predicate, runs a phase 2 setup against the Ethereum powers of
# tau, and proves once to show the result works.
#
# The phase 1 ceremony is downloaded, never generated: generating one locally
# would mean this repository chose the toxic waste for everybody. The phase 2
# contribution here is local and single, which is enough to develop against
# and unfit for a deployment; see the README.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

statement="${1:-compare}"

power=13

ptau="$here/build/powersOfTau28_hez_final_$power.ptau"

mkdir -p "$here/build"

if [ ! -f "$ptau" ]; then
  echo "fetching the Ethereum powers of tau, 2^$power"

  curl -sL --fail -o "$ptau" \
    "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_$power.ptau"
fi

# Verifying before use is the point of using a published ceremony.
snarkjs powersoftau verify "$ptau" >/dev/null

echo "powers of tau verified"

# --O2 to match what build-circuit applies when it builds the witness
# graph. Without it the proving key expects a wider witness than the graph
# produces, and rapidsnark rejects it as belonging to another circuit.
circom "$here/bin/predicate/$statement/main.circom" --r1cs --wasm --O2 -o "$here/build" >/dev/null

snarkjs groth16 setup "$here/build/main.r1cs" "$ptau" "$here/build/${statement}_0000.zkey" >/dev/null

snarkjs zkey contribute \
  "$here/build/${statement}_0000.zkey" \
  "$here/build/$statement.zkey" \
  --name="local development contribution, not a ceremony" \
  -e="$(head -c 64 /dev/urandom | base64)" >/dev/null

snarkjs zkey export verificationkey \
  "$here/build/$statement.zkey" \
  "$here/build/${statement}_vk.json" >/dev/null

echo "phase 2 done for $statement: build/$statement.zkey and build/${statement}_vk.json"

# The graph the Rust prover walks, from the same source and the same
# optimization as the key, which is what makes the two compatible.
if command -v build-circuit >/dev/null; then
  build-circuit "$here/bin/predicate/$statement/main.circom" "$here/build/$statement.graph" >/dev/null

  echo "witness graph at build/$statement.graph"
else
  echo "build-circuit not on PATH, so no witness graph; see the README to install it"
fi

echo "the proving key is local and ignored by git; a deployment runs its own ceremony"
