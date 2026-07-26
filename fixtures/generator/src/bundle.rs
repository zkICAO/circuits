//! Proves a whole document and checks the result, end to end.
//!
//! Each circuit is executed in chain order and its outputs are read back and
//! written into the next one's witness, which is how a bundle comes to
//! describe one document rather than several. Every proof is then produced
//! and verified with the backend.
//!
//! This is the check that the pieces fit together. Unit tests exercise each
//! circuit against fixtures, and nothing but this exercises the chain with
//! real proofs, which is where a mistake in a binding value would show.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::ec;
use crate::icao;
use crate::scratch::Scratch;

const ECONTENT_BUFFER: usize = 512;

const SIGNED_ATTRS_BUFFER: usize = 256;

const DG1_BUFFER: usize = 128;

const DOMAIN: &str = "42";

const CONTEXT: &str = "99";

const DSC_SALT: &str = "7";

const SESSION_SALT: &str = "123456789";

const TODAY: &str = "20260725";

/// The birth date field, which a range proof turns into an age check.
const BIRTH_DATE_FIELD: &str = "5";

const NATIONALITY_FIELD: &str = "4";

const ISSUING_STATE_FIELD: &str = "2";

const DOCUMENT_NUMBER_FIELD: &str = "3";

pub struct Bundle {
    pub directory: PathBuf,
    pub econtent_binding: String,
    pub dg_binding: String,
    pub commitment: String,
    pub secret_binding: String,
    pub registry_root: String,
    pub nullifier: String,
}

/// With `proving` off the chain runs without producing proofs. The links
/// between circuits come from executing them and feeding each one's outputs
/// into the next, so leaving proving out still catches a broken link, and it
/// lets continuous integration run this without the backend installed.
pub fn build(circuits_root: &Path, out: &Path, proving: bool) -> Bundle {
    let work = Scratch::new("bundle");

    let key = ec::generate(&ec::P256, &work.join("dsc.pem"));

    let dg1 = icao::build_dg1(icao::MRZ_TD3);

    let groups = vec![
        icao::DataGroup {
            number: 1,
            content: dg1.clone(),
        },
        icao::DataGroup {
            number: 2,
            content: vec![0x5a; 96],
        },
    ];

    let security_object = icao::build_security_object(&groups);

    let signed_attrs = icao::build_signed_attributes(&security_object.econtent);

    let signature = ec::sign_sha256(&key, &signed_attrs.bytes);

    let dg1_offset = security_object
        .dg_offsets
        .iter()
        .find(|(number, _)| *number == 1)
        .expect("the security object must cover DG1")
        .1;

    // Without proving there is nothing to write, and touching the directory
    // would leave proofs from an earlier run beside values from this one,
    // which reads as a bundle that was checked and was not.
    if proving {
        std::fs::remove_dir_all(out).ok();

        std::fs::create_dir_all(out).expect("cannot create the bundle directory");
    }

    // 1. The issuing state signed this document.
    let mut witness = String::new();

    bytes(
        &mut witness,
        "econtent",
        &security_object.econtent,
        ECONTENT_BUFFER,
    );
    value(
        &mut witness,
        "econtent_len",
        &security_object.econtent.len().to_string(),
    );
    bytes(
        &mut witness,
        "signed_attrs",
        &signed_attrs.bytes,
        SIGNED_ATTRS_BUFFER,
    );
    value(
        &mut witness,
        "signed_attrs_len",
        &signed_attrs.bytes.len().to_string(),
    );
    value(
        &mut witness,
        "digest_offset",
        &signed_attrs.digest_offset.to_string(),
    );
    bytes(&mut witness, "pubkey_x", &key.public_x, 32);
    bytes(&mut witness, "pubkey_y", &key.public_y, 32);
    bytes(&mut witness, "signature_r", &signature.r, 32);
    bytes(&mut witness, "signature_s", &signature.s, 32);
    value(&mut witness, "dsc_salt", DSC_SALT);
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "context", CONTEXT);

    let sod = run_circuit(circuits_root, "sod_ecdsa_p256_sha256_ec512", &witness);

    let econtent_binding = sod[0].clone();

    let dsc_commitment = sod[1].clone();

    let secret_binding = sod[2].clone();

    prove(
        circuits_root,
        out,
        "sod_ecdsa_p256_sha256_ec512",
        "sod",
        proving,
    );

    // 2. That signed object commits to this data group.
    let mut witness = String::new();

    bytes(
        &mut witness,
        "econtent",
        &security_object.econtent,
        ECONTENT_BUFFER,
    );
    value(
        &mut witness,
        "econtent_len",
        &security_object.econtent.len().to_string(),
    );
    value(
        &mut witness,
        "oid_offset",
        &security_object.oid_offset.to_string(),
    );
    value(&mut witness, "dg_offset", &dg1_offset.to_string());
    value(&mut witness, "dg_number", "1");
    value(&mut witness, "econtent_binding", &econtent_binding);
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "context", CONTEXT);

    let dg_binding = run_circuit(circuits_root, "dg_extract_sha256_ec512", &witness)[0].clone();

    prove(
        circuits_root,
        out,
        "dg_extract_sha256_ec512",
        "dg_extract",
        proving,
    );

    // 3. The fields of that data group, committed.
    let mut witness = String::new();

    bytes(&mut witness, "dg1", &dg1, DG1_BUFFER);
    value(&mut witness, "dg1_len", &dg1.len().to_string());
    value(&mut witness, "session_salt", SESSION_SALT);
    value(&mut witness, "dg_binding", &dg_binding);
    value(&mut witness, "current_yyyymmdd", TODAY);
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "context", CONTEXT);

    let commitment = run_circuit(circuits_root, "attributes_mrz_td3_sha256", &witness)[0].clone();

    prove(
        circuits_root,
        out,
        "attributes_mrz_td3_sha256",
        "attributes",
        proving,
    );

    // 4. The witness for the birth date field.
    let opening = opening_for(circuits_root, &dg1, BIRTH_DATE_FIELD);

    // 5. Born on or before the cutoff, without saying when.
    let mut witness = String::new();

    value(&mut witness, "length", &opening[4]);
    array(&mut witness, "data", &opening[0..4]);
    value(&mut witness, "entropy", &opening[5]);
    array(&mut witness, "siblings", &opening[6..10]);
    value(&mut witness, "field_id", BIRTH_DATE_FIELD);
    value(&mut witness, "commitment", &commitment);
    value(&mut witness, "minimum", "0");
    value(&mut witness, "maximum", "20080725");
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "context", CONTEXT);

    run_circuit(circuits_root, "predicate_compare", &witness);

    prove(
        circuits_root,
        out,
        "predicate_compare",
        "predicate_compare",
        proving,
    );

    // 5b. The nationality is in a list the verifier publishes. The set
    //    siblings stand for the rest of that list; the root comes from the
    //    tool so it is the same hashing the circuit recomputes.
    let nationality = opening_for(circuits_root, &dg1, NATIONALITY_FIELD);

    let set_siblings: Vec<String> = (0..8).map(|level| (level + 600).to_string()).collect();

    let mut witness = String::new();

    array(&mut witness, "data", &nationality[0..4]);
    array(&mut witness, "set_siblings", &set_siblings);

    let set_root = run_circuit(circuits_root, "set_witness", &witness)[0].clone();

    let mut witness = String::new();

    value(&mut witness, "length", &nationality[4]);
    array(&mut witness, "data", &nationality[0..4]);
    value(&mut witness, "entropy", &nationality[5]);
    array(&mut witness, "siblings", &nationality[6..10]);
    value(&mut witness, "set_index", "0");
    array(&mut witness, "set_siblings", &set_siblings);
    value(&mut witness, "field_id", NATIONALITY_FIELD);
    value(&mut witness, "commitment", &commitment);
    value(&mut witness, "set_root", &set_root);
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "context", CONTEXT);

    run_circuit(circuits_root, "predicate_member", &witness);

    prove(
        circuits_root,
        out,
        "predicate_member",
        "predicate_member",
        proving,
    );

    // 6. The signer is one this verifier trusts. The siblings stand for the
    //    rest of a published registry; a real one supplies them from its own
    //    tree. The leaf and the root come from the tool, so they are the same
    //    hashes the circuit recomputes rather than a second implementation.
    let siblings: Vec<String> = (0..16).map(|level| (level + 700).to_string()).collect();

    let mut witness = String::new();

    bytes(&mut witness, "pubkey_x", &key.public_x, 32);
    bytes(&mut witness, "pubkey_y", &key.public_y, 32);
    array(&mut witness, "siblings", &siblings);

    let registry_root = run_circuit(circuits_root, "registry_witness", &witness)[1].clone();

    let mut witness = String::new();

    bytes(&mut witness, "pubkey_x", &key.public_x, 32);
    bytes(&mut witness, "pubkey_y", &key.public_y, 32);
    value(&mut witness, "salt", DSC_SALT);
    value(&mut witness, "index", "0");
    array(&mut witness, "siblings", &siblings);
    value(&mut witness, "registry_root", &registry_root);
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "context", CONTEXT);

    let anchor = run_circuit(circuits_root, "anchor_dsc_inclusion", &witness);

    assert_eq!(
        anchor[0], dsc_commitment,
        "the anchor must commit to the key that signed the document"
    );

    prove(
        circuits_root,
        out,
        "anchor_dsc_inclusion",
        "anchor",
        proving,
    );

    // 7. One value per holder per application. It needs the secret that the
    //    Security Object proof published only a binding to.
    let mut witness = String::new();

    bytes(&mut witness, "signature_r", &signature.r, 32);
    bytes(&mut witness, "signature_s", &signature.s, 32);

    let secret = run_circuit(circuits_root, "document_secret", &witness)[0].clone();

    let state = opening_for(circuits_root, &dg1, ISSUING_STATE_FIELD);

    let number = opening_for(circuits_root, &dg1, DOCUMENT_NUMBER_FIELD);

    let mut witness = String::new();

    value(&mut witness, "state_length", &state[4]);
    array(&mut witness, "state_data", &state[0..4]);
    value(&mut witness, "state_entropy", &state[5]);
    array(&mut witness, "state_siblings", &state[6..10]);
    value(&mut witness, "number_length", &number[4]);
    array(&mut witness, "number_data", &number[0..4]);
    value(&mut witness, "number_entropy", &number[5]);
    array(&mut witness, "number_siblings", &number[6..10]);
    value(&mut witness, "secret", &secret);
    value(&mut witness, "commitment", &commitment);
    value(&mut witness, "secret_binding", &secret_binding);
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "context", CONTEXT);

    let nullifier = run_circuit(circuits_root, "nullifier_document_number", &witness)[0].clone();

    prove(
        circuits_root,
        out,
        "nullifier_document_number",
        "nullifier",
        proving,
    );

    // 8. The four document proofs folded into one recursive proof. The
    //    witness needs the inner proofs themselves, so this step exists only
    //    when proving. The key hashes are compiled into the circuit, which is
    //    what makes proving fail against any other variant set.
    if proving {
        let mut witness = String::new();

        for (prefix, name) in [
            ("sod", "sod"),
            ("dg_extract", "dg_extract"),
            ("attributes", "attributes"),
            ("anchor", "anchor"),
        ] {
            field_elements(
                &mut witness,
                &format!("{prefix}_key"),
                &out.join(name).join("vk"),
            );

            field_elements(
                &mut witness,
                &format!("{prefix}_proof"),
                &out.join(name).join("proof"),
            );
        }

        value(&mut witness, "econtent_binding", &econtent_binding);
        value(&mut witness, "dsc_commitment", &dsc_commitment);
        value(&mut witness, "secret_binding", &secret_binding);
        value(&mut witness, "dg_binding", &dg_binding);
        value(&mut witness, "commitment", &commitment);
        value(&mut witness, "current_yyyymmdd", TODAY);
        value(&mut witness, "registry_root", &registry_root);
        value(&mut witness, "domain", DOMAIN);
        value(&mut witness, "context", CONTEXT);

        let registration = run_circuit(
            circuits_root,
            "registration_mrz_td3_ecdsa_p256_sha256_ec512_inclusion",
            &witness,
        );

        assert_eq!(
            registration[0], commitment,
            "the registration proof must expose the commitment it aggregated"
        );

        assert_eq!(
            registration[1], secret_binding,
            "the registration proof must expose the secret binding it aggregated"
        );

        assert_eq!(
            numeric(&registration[2]),
            numeric(TODAY),
            "the registration proof must expose the date the attributes resolved against"
        );

        assert_eq!(
            registration[3], registry_root,
            "the registration proof must expose the registry it anchored to"
        );

        prove(
            circuits_root,
            out,
            "registration_mrz_td3_ecdsa_p256_sha256_ec512_inclusion",
            "registration",
            proving,
        );

        // 9. The two predicates of the session folded into one proof, the
        //    aggregation a session uses when it asks more than one question.
        let mut witness = String::new();

        field_elements(
            &mut witness,
            "compare_key",
            &out.join("predicate_compare/vk"),
        );

        field_elements(
            &mut witness,
            "compare_proof",
            &out.join("predicate_compare/proof"),
        );

        field_elements(&mut witness, "member_key", &out.join("predicate_member/vk"));

        field_elements(
            &mut witness,
            "member_proof",
            &out.join("predicate_member/proof"),
        );

        value(&mut witness, "commitment", &commitment);
        value(&mut witness, "compare_field_id", BIRTH_DATE_FIELD);
        value(&mut witness, "minimum", "0");
        value(&mut witness, "maximum", "20080725");
        value(&mut witness, "member_field_id", NATIONALITY_FIELD);
        value(&mut witness, "set_root", &set_root);
        value(&mut witness, "domain", DOMAIN);
        value(&mut witness, "context", CONTEXT);

        let session = run_circuit(circuits_root, "session_compare_member", &witness);

        assert_eq!(
            session[0], commitment,
            "the session proof must expose the commitment its predicates opened"
        );

        prove(
            circuits_root,
            out,
            "session_compare_member",
            "session",
            proving,
        );
    }

    Bundle {
        directory: out.to_path_buf(),
        econtent_binding,
        dg_binding,
        commitment,
        secret_binding,
        registry_root,
        nullifier,
    }
}

/// The opening for one field, from the tool that shares the attribute
/// circuit's derivation.
fn opening_for(circuits_root: &Path, dg1: &[u8], field_id: &str) -> Vec<String> {
    let mut witness = String::new();

    bytes(&mut witness, "dg1", dg1, DG1_BUFFER);
    value(&mut witness, "dg1_len", &dg1.len().to_string());
    value(&mut witness, "session_salt", SESSION_SALT);
    value(&mut witness, "domain", DOMAIN);
    value(&mut witness, "current_yyyymmdd", TODAY);
    value(&mut witness, "field_id", field_id);

    let opening = run_circuit(circuits_root, "mrz_opening", &witness);

    assert_eq!(
        opening.len(),
        10,
        "an opening is four data elements, a length, an entropy and four siblings"
    );

    opening
}

/// Writes a witness, solves it, and returns the circuit outputs in order.
fn run_circuit(circuits_root: &Path, package: &str, witness: &str) -> Vec<String> {
    let package_dir = find_package(circuits_root, package);

    std::fs::write(package_dir.join("Prover.toml"), witness).expect("cannot write a witness");

    let output = ec::run(
        "nargo",
        &[
            "execute",
            "--package",
            package,
            "--program-dir",
            circuits_root.to_str().unwrap(),
        ],
        None,
    );

    let text = String::from_utf8_lossy(&output);

    parse_outputs(&text)
}

/// nargo prints the outputs of a solved circuit on one line, as a tuple with
/// nested arrays. Field elements come out in hex and integers in decimal, so
/// this tokenizes rather than looking for one shape: reading only the hex
/// values silently drops every integer output.
fn parse_outputs(text: &str) -> Vec<String> {
    // A circuit that only asserts returns nothing and prints no output line.
    // That is not a failure: a failed execution never reaches here, because
    // the command runner requires the process to have succeeded.
    let Some(line) = text.lines().find(|line| line.contains("Circuit output")) else {
        assert!(
            text.contains("successfully solved"),
            "nargo neither solved the witness nor printed an output:\n{text}"
        );

        return Vec::new();
    };

    let body = line
        .split_once("Circuit output:")
        .map(|(_, tail)| tail)
        .unwrap_or(line);

    body.split(|c: char| {
        c == ',' || c == '[' || c == ']' || c == '(' || c == ')' || c.is_whitespace()
    })
    .map(str::trim)
    .filter(|token| !token.is_empty())
    .map(str::to_string)
    .collect()
}

fn find_package(circuits_root: &Path, package: &str) -> PathBuf {
    for relative in ["bin", "tools"] {
        let root = circuits_root.join(relative);

        if let Some(found) = search(&root, package) {
            return found;
        }
    }

    panic!("cannot find the package {package}");
}

fn search(directory: &Path, package: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(directory).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let manifest = path.join("Nargo.toml");

        if manifest.exists() {
            let text = std::fs::read_to_string(&manifest).unwrap_or_default();

            if text.contains(&format!("name = \"{package}\"")) {
                return Some(path);
            }
        }

        if let Some(found) = search(&path, package) {
            return Some(found);
        }
    }

    None
}

/// Produces the verification key, the proof and the public inputs, then
/// checks the proof before it goes into the bundle. A bundle containing a
/// proof that does not verify would send anyone reading it in the wrong
/// direction.
fn prove(circuits_root: &Path, out: &Path, package: &str, name: &str, proving: bool) {
    if !proving {
        println!("  {name}: executed");

        return;
    }

    let directory = out.join(name);

    std::fs::create_dir_all(&directory).expect("cannot create a bundle entry");

    let bytecode = circuits_root.join(format!("target/{package}.json"));

    let solved = circuits_root.join(format!("target/{package}.gz"));

    ec::run(
        "bb",
        &[
            "write_vk",
            "-b",
            bytecode.to_str().unwrap(),
            "-o",
            directory.to_str().unwrap(),
        ],
        None,
    );

    ec::run(
        "bb",
        &[
            "prove",
            "-b",
            bytecode.to_str().unwrap(),
            "-w",
            solved.to_str().unwrap(),
            "-k",
            directory.join("vk").to_str().unwrap(),
            "-o",
            directory.to_str().unwrap(),
        ],
        None,
    );

    ec::run(
        "bb",
        &[
            "verify",
            "-k",
            directory.join("vk").to_str().unwrap(),
            "-p",
            directory.join("proof").to_str().unwrap(),
            "-i",
            directory.join("public_inputs").to_str().unwrap(),
        ],
        None,
    );

    println!("  {name}: proved and verified");
}

/// Writes a file of whole 32 byte field elements as a witness array, which is
/// how a verification key or a proof enters the registration witness: the
/// binary bb writes is already field elements laid end to end.
fn field_elements(witness: &mut String, name: &str, path: &Path) {
    let data =
        std::fs::read(path).expect("a bundle entry the registration witness needs is missing");

    assert!(
        data.len().is_multiple_of(32),
        "field element data must be whole 32 byte elements"
    );

    let fields: Vec<String> = data
        .chunks(32)
        .map(|chunk| {
            let mut element = String::from("0x");

            for byte in chunk {
                write!(element, "{byte:02x}").unwrap();
            }

            element
        })
        .collect();

    array(witness, name, &fields);
}

/// Reads a value nargo may have printed in hex or that a constant states in
/// decimal, for comparing the two.
fn numeric(text: &str) -> u64 {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).expect("a numeric output does not fit")
    } else {
        text.parse().expect("a numeric output does not parse")
    }
}

fn bytes(out: &mut String, name: &str, value: &[u8], width: usize) {
    assert!(value.len() <= width, "{name} does not fit its buffer");

    write!(out, "{name} = [").unwrap();

    for index in 0..width {
        let byte = if index < value.len() { value[index] } else { 0 };

        write!(out, "\"{byte}\", ").unwrap();
    }

    out.push_str("]\n");
}

fn array(out: &mut String, name: &str, values: &[String]) {
    write!(out, "{name} = [").unwrap();

    for value in values {
        write!(out, "\"{value}\", ").unwrap();
    }

    out.push_str("]\n");
}

fn value(out: &mut String, name: &str, value: &str) {
    writeln!(out, "{name} = \"{value}\"").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_output_of_a_solved_circuit() {
        let line = "[pkg] Circuit output: (0x2bbe, 0x180f, 0x1d17)";

        assert_eq!(parse_outputs(line), vec!["0x2bbe", "0x180f", "0x1d17"]);
    }

    // A predicate only asserts, so it returns nothing and prints no output.
    #[test]
    fn accepts_a_circuit_that_returns_nothing() {
        assert!(parse_outputs("[pkg] Circuit witness successfully solved").is_empty());
    }

    #[test]
    #[should_panic(expected = "neither solved the witness nor printed an output")]
    fn refuses_output_it_cannot_account_for() {
        let _ = parse_outputs("something else entirely");
    }

    #[test]
    fn reads_a_single_output() {
        assert_eq!(parse_outputs("Circuit output: 0xabc"), vec!["0xabc"]);
    }

    // Integers print in decimal while field elements print in hex, and the
    // opening tool returns both. A parser that looked only for hex dropped
    // the length and shifted every value after it.
    #[test]
    fn reads_a_tuple_of_arrays_mixing_hex_and_decimal() {
        let line = "[pkg] Circuit output: ([0x012d, 0x00, 0x00, 0x00], 8, 0x0e99, [0x18a3, 0x0b26, 0x1ec3, 0x2aeb])";

        assert_eq!(
            parse_outputs(line),
            vec![
                "0x012d", "0x00", "0x00", "0x00", "8", "0x0e99", "0x18a3", "0x0b26", "0x1ec3",
                "0x2aeb"
            ]
        );
    }
}
