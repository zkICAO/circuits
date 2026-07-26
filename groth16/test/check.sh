#!/usr/bin/env bash
# Checks that this stack computes what the Noir stack computes.
#
# A predicate here opens a commitment the Noir attribute circuit produced. If
# the two disagree by one field element the predicate proves nothing about
# the document, and it fails silently: both proofs still verify against their
# own verification keys. So the agreement is checked, twice, rather than
# inferred from the constants matching.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

circuits="$(cd "$here/.." && pwd)"

work="$(mktemp -d)"

trap 'rm -rf "$work"' EXIT

echo "1. the hash, at every width the protocol uses"

# The vectors come from Noir, computed by the tool that shares the library
# the circuits use.
vectors=$(cd "$circuits" && nargo execute --package hash_vectors 2>&1 | grep 'Circuit output')

python3 - "$vectors" "$work" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

values = re.findall(r'0x[0-9a-f]{64}', sys.argv[1])

if len(values) < 5:
    print('the Noir tool printed no vectors', file=sys.stderr)

    raise SystemExit(1)

Path(sys.argv[2], 'noir.json').write_text(json.dumps([int(v, 16) for v in values[:5]]))

# The circom side still takes them, since a circom main has inputs.
Path(sys.argv[2], 'in.json').write_text(json.dumps({'a': '1', 'b': '2', 'c': '3', 'd': '4'}))
PYEOF

circom "$here/test/vectors.circom" --wasm -o "$work" >/dev/null

node "$work/vectors_js/generate_witness.js" \
  "$work/vectors_js/vectors.wasm" "$work/in.json" "$work/vectors.wtns" >/dev/null

snarkjs wtns export json "$work/vectors.wtns" "$work/vectors.json" >/dev/null

python3 - "$work" <<'PYEOF'
import json
import sys
from pathlib import Path

work = Path(sys.argv[1])

witness = json.loads((work / 'vectors.json').read_text())

noir = json.loads((work / 'noir.json').read_text())

# Signal one onwards are the outputs, in declaration order.
circom = [int(witness[i]) for i in range(1, 1 + len(noir))]

widths = [2, 3, 4, 5, 8]

for width, got, want in zip(widths, circom, noir):
    if got != want:
        print(f'   width {width}: DIFFERS', file=sys.stderr)

        print(f'     circom 0x{got:064x}', file=sys.stderr)

        print(f'     noir   0x{want:064x}', file=sys.stderr)

        raise SystemExit(1)

    print(f'   width {width}: agrees')
PYEOF

echo "2. a whole opening, from a commitment the Noir circuits made"

opening="$circuits/bin/predicate/compare/Prover.toml"

membership="$circuits/bin/predicate/member/Prover.toml"

if [ ! -f "$opening" ] || [ ! -f "$membership" ]; then
  echo "   skipped: no witnesses beside the Noir predicates, run the bundle command first"

  exit 0
fi

python3 - "$opening" "$work" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

toml = Path(sys.argv[1]).read_text()


def number(text):
    return str(int(text, 16) if text.startswith('0x') else int(text))


def scalar(name):
    return number(re.search(rf'^{name} = "([^"]+)"', toml, re.M).group(1))


def array(name):
    body = re.search(rf'^{name} = \[(.*?)\]', toml, re.M | re.S).group(1)

    return [number(v) for v in re.findall(r'"([^"]+)"', body)]


Path(sys.argv[2], 'opening.json').write_text(
    json.dumps(
        {
            'fieldId': scalar('field_id'),
            'commitment': scalar('commitment'),
            'minimum': scalar('minimum'),
            'maximum': scalar('maximum'),
            'domain': scalar('domain'),
            'length': scalar('length'),
            'data': array('data'),
            'entropy': scalar('entropy'),
            'siblings': array('siblings'),
        }
    )
)
PYEOF

circom "$here/bin/predicate/compare/main.circom" --wasm -o "$work" >/dev/null

node "$work/main_js/generate_witness.js" \
  "$work/main_js/main.wasm" "$work/opening.json" "$work/opening.wtns" >/dev/null

echo "   the circom predicate opens it"

# The other two statements open the same commitment, so each is checked
# against the witness the Noir circuit of that name was given.
python3 - "$membership" "$opening" "$work" <<'PYEOF2'
import json
import re
import sys
from pathlib import Path


def read(path):
    return Path(path).read_text()


def number(text):
    return str(int(text, 16) if text.startswith('0x') else int(text))


def scalar(toml, name):
    return number(re.search(rf'^{name} = "([^"]+)"', toml, re.M).group(1))


def array(toml, name):
    body = re.search(rf'^{name} = \[(.*?)\]', toml, re.M | re.S).group(1)

    return [number(v) for v in re.findall(r'"([^"]+)"', body)]


member = read(sys.argv[1])

compare = read(sys.argv[2])

work = Path(sys.argv[3])

(work / 'member.json').write_text(
    json.dumps(
        {
            'fieldId': scalar(member, 'field_id'),
            'commitment': scalar(member, 'commitment'),
            'setRoot': scalar(member, 'set_root'),
            'domain': scalar(member, 'domain'),
            'length': scalar(member, 'length'),
            'data': array(member, 'data'),
            'entropy': scalar(member, 'entropy'),
            'siblings': array(member, 'siblings'),
            'setIndex': scalar(member, 'set_index'),
            'setSiblings': array(member, 'set_siblings'),
        }
    )
)

# No Noir reveal witness is produced by the bundle, so the compare opening
# is disclosed instead: the same field, a different statement about it.
(work / 'reveal.json').write_text(
    json.dumps(
        {
            'fieldId': scalar(compare, 'field_id'),
            'commitment': scalar(compare, 'commitment'),
            'revealed': array(compare, 'data'),
            'revealedLength': scalar(compare, 'length'),
            'domain': scalar(compare, 'domain'),
            'entropy': scalar(compare, 'entropy'),
            'siblings': array(compare, 'siblings'),
        }
    )
)
PYEOF2

for statement in member reveal; do
  mkdir -p "$work/$statement"

  circom "$here/bin/predicate/$statement/main.circom" --wasm -o "$work/$statement" >/dev/null

  node "$work/$statement/main_js/generate_witness.js" \
    "$work/$statement/main_js/main.wasm" "$work/$statement.json" "$work/$statement.wtns" >/dev/null

  echo "   the circom $statement predicate opens it too"
done

echo "3. and refuses openings it should"

python3 - "$work" <<'PYEOF'
import json
import sys
from pathlib import Path

work = Path(sys.argv[1])

base = json.loads((work / 'opening.json').read_text())

cases = {
    'a tampered value': lambda i: i.update(data=[str(int(i['data'][0]) + 1)] + i['data'][1:]),
    'another commitment': lambda i: i.update(commitment=str(int(i['commitment']) ^ 1)),
    'another field identifier': lambda i: i.update(fieldId='7'),
    'a value outside the range': lambda i: i.update(maximum='19000101'),
    'an empty range': lambda i: i.update(minimum='30000000', maximum='1'),
    'a tampered sibling': lambda i: i.update(siblings=[str(int(i['siblings'][0]) ^ 1)] + i['siblings'][1:]),
}

names = []

for index, (name, mutate) in enumerate(cases.items()):
    case = json.loads(json.dumps(base))

    mutate(case)

    (work / f'bad{index}.json').write_text(json.dumps(case))

    names.append(name)

(work / 'names.json').write_text(json.dumps(names))
PYEOF

count=$(python3 -c "import json,sys; print(len(json.load(open('$work/names.json'))))")

for index in $(seq 0 $((count - 1))); do
  name=$(python3 -c "import json; print(json.load(open('$work/names.json'))[$index])")

  if node "$work/main_js/generate_witness.js" \
      "$work/main_js/main.wasm" "$work/bad$index.json" "$work/bad.wtns" >/dev/null 2>&1; then
    echo "   $name: ACCEPTED, which is a hole" >&2

    exit 1
  fi

  echo "   $name: refused"
done

echo
echo "the two stacks agree"
