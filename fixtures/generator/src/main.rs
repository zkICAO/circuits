//! Generates synthetic ICAO Doc 9303 test vectors and writes them out as a
//! Noir library, so circuit tests run against a complete signed document
//! without reading files at proving time.
//!
//! The documents are synthetic: keys are generated here and the specimen
//! machine readable zones are the ones Doc 9303 publishes as examples. No
//! genuine document is involved, and regenerating produces a fresh key, so
//! the committed output is the fixture of record.

mod bigint;
mod bundle;
mod cert;
mod der;
mod ec;
mod icao;
mod keys;
mod manifest;
mod rsa;
mod scratch;
mod templates;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const ECONTENT_BUFFER: usize = 512;

const SIGNED_ATTRS_BUFFER: usize = 256;

const DG1_BUFFER: usize = 128;

const CERTIFICATE_BUFFER: usize = 512;

struct Document {
    prefix: &'static str,
    mrz: &'static str,
    mrz_len: usize,
}

fn main() {
    // Three jobs: refresh the committed fixtures, prove a document all the way
    // through and check the result, or write the layout the verifier reads.
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        let circuits_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("unexpected generator location");

        let destination = std::env::args()
            .nth(2)
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                circuits_root
                    .parent()
                    .expect("unexpected checkout layout")
                    .join("prover/layout.manifest")
            });

        manifest::write(circuits_root, &destination);

        return;
    }

    if std::env::args().nth(1).as_deref() == Some("templates") {
        let circuits_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("unexpected generator location");

        templates::write(circuits_root);

        return;
    }

    if std::env::args().nth(1).as_deref() == Some("keys") {
        let circuits_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("unexpected generator location");

        // The check form recomputes and compares instead of writing, so a
        // circuit changed without regenerating fails here rather than as a
        // proof that will not verify.
        if std::env::args().nth(2).as_deref() == Some("--check") {
            if keys::check(circuits_root) {
                println!("every recursive circuit pins the hashes its inner circuits have now");
            } else {
                eprintln!(
                    "a recursive circuit pins a stale verification key hash; \
                     run `cargo run -- keys` and commit the result"
                );

                std::process::exit(1);
            }

            return;
        }

        keys::write(circuits_root);

        return;
    }

    if std::env::args().nth(1).as_deref() == Some("bundle") {
        let proving = std::env::args().nth(2).as_deref() != Some("--no-prove");

        let circuits_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("unexpected generator location");

        let out = circuits_root.join("target/bundle");

        let result = bundle::build(circuits_root, &out, proving);

        println!();

        if proving {
            println!("bundle written to {}", result.directory.display());
        } else {
            println!("chain executed, no proofs produced and nothing written");
        }

        println!("  econtent binding {}", result.econtent_binding);

        println!("  dg binding       {}", result.dg_binding);

        println!("  commitment       {}", result.commitment);

        println!("  secret binding   {}", result.secret_binding);

        println!("  registry root    {}", result.registry_root);

        println!("  nullifier        {}", result.nullifier);

        return;
    }

    let out_path = target_path();

    let work_dir = scratch::Scratch::new("fixtures");

    let documents = [
        Document {
            prefix: "TD3",
            mrz: icao::MRZ_TD3,
            mrz_len: 88,
        },
        Document {
            prefix: "TD2",
            mrz: icao::MRZ_TD2,
            mrz_len: 72,
        },
        Document {
            prefix: "TD1",
            mrz: icao::MRZ_TD1,
            mrz_len: 90,
        },
    ];

    let mut body = String::new();

    body.push_str(HEADER);

    for (index, document) in documents.iter().enumerate() {
        assert_eq!(
            document.mrz.len(),
            document.mrz_len,
            "specimen length mismatch"
        );

        let key = ec::generate(&ec::P256, &work_dir.join(&format!("dsc{index}.pem")));

        emit_document(&mut body, document, &key);

        if index == 0 {
            emit_prover_toml(document, &key);
        }
    }

    emit_rsa_document(&mut body, &work_dir);

    emit_certificate_chain(&mut body, &work_dir);

    emit_chip_key(&mut body, &work_dir);

    std::fs::write(&out_path, body).expect("cannot write the fixture library");

    println!("wrote {}", out_path.display());
}

fn target_path() -> PathBuf {
    let generator_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let circuits_root = generator_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("unexpected generator location");

    let dir = circuits_root.join("lib/testdata/src");

    std::fs::create_dir_all(&dir).expect("cannot create the testdata package");

    dir.join("lib.nr")
}

fn emit_document(body: &mut String, document: &Document, key: &ec::KeyPair) {
    let dg1 = icao::build_dg1(document.mrz);

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

    let signature = ec::sign_sha256(key, &signed_attrs.bytes);

    let prefix = document.prefix;

    writeln!(
        body,
        "// {prefix} document, signed with a generated P-256 Document Signer key."
    )
    .unwrap();

    emit_bytes(
        body,
        &format!("{prefix}_MRZ"),
        document.mrz.as_bytes(),
        document.mrz_len,
    );

    emit_bytes(body, &format!("{prefix}_DG1"), &dg1, DG1_BUFFER);

    emit_u32(body, &format!("{prefix}_DG1_LEN"), dg1.len());

    emit_bytes(
        body,
        &format!("{prefix}_ECONTENT"),
        &security_object.econtent,
        ECONTENT_BUFFER,
    );

    emit_u32(
        body,
        &format!("{prefix}_ECONTENT_LEN"),
        security_object.econtent.len(),
    );

    emit_u32(
        body,
        &format!("{prefix}_OID_OFFSET"),
        security_object.oid_offset,
    );

    for (number, offset) in &security_object.dg_offsets {
        emit_u32(body, &format!("{prefix}_DG{number}_OFFSET"), *offset);
    }

    emit_bytes(
        body,
        &format!("{prefix}_SIGNED_ATTRS"),
        &signed_attrs.bytes,
        SIGNED_ATTRS_BUFFER,
    );

    emit_u32(
        body,
        &format!("{prefix}_SIGNED_ATTRS_LEN"),
        signed_attrs.bytes.len(),
    );

    emit_u32(
        body,
        &format!("{prefix}_DIGEST_OFFSET"),
        signed_attrs.digest_offset,
    );

    emit_bytes(
        body,
        &format!("{prefix}_DSC_PUBKEY_X"),
        &key.public_x,
        key.curve.scalar_bytes,
    );

    emit_bytes(
        body,
        &format!("{prefix}_DSC_PUBKEY_Y"),
        &key.public_y,
        key.curve.scalar_bytes,
    );

    emit_bytes(
        body,
        &format!("{prefix}_SIGNATURE_R"),
        &signature.r,
        key.curve.scalar_bytes,
    );

    emit_bytes(
        body,
        &format!("{prefix}_SIGNATURE_S"),
        &signature.s,
        key.curve.scalar_bytes,
    );

    body.push('\n');
}

/// Writes the witness for the Passive Authentication circuit, so the whole
/// pipeline can be proved and verified outside the test harness.
fn emit_prover_toml(document: &Document, key: &ec::KeyPair) {
    let dg1 = icao::build_dg1(document.mrz);

    let groups = vec![
        icao::DataGroup {
            number: 1,
            content: dg1,
        },
        icao::DataGroup {
            number: 2,
            content: vec![0x5a; 96],
        },
    ];

    let security_object = icao::build_security_object(&groups);

    let signed_attrs = icao::build_signed_attributes(&security_object.econtent);

    let signature = ec::sign_sha256(key, &signed_attrs.bytes);

    let mut toml = String::new();

    toml_bytes(
        &mut toml,
        "econtent",
        &security_object.econtent,
        ECONTENT_BUFFER,
    );

    toml_value(&mut toml, "econtent_len", security_object.econtent.len());

    toml_bytes(
        &mut toml,
        "signed_attrs",
        &signed_attrs.bytes,
        SIGNED_ATTRS_BUFFER,
    );

    toml_value(&mut toml, "signed_attrs_len", signed_attrs.bytes.len());

    toml_value(&mut toml, "digest_offset", signed_attrs.digest_offset);

    toml_bytes(&mut toml, "pubkey_x", &key.public_x, key.curve.scalar_bytes);

    toml_bytes(&mut toml, "pubkey_y", &key.public_y, key.curve.scalar_bytes);

    toml_bytes(
        &mut toml,
        "signature_r",
        &signature.r,
        key.curve.scalar_bytes,
    );

    toml_bytes(
        &mut toml,
        "signature_s",
        &signature.s,
        key.curve.scalar_bytes,
    );

    toml_value(&mut toml, "dsc_salt", 7);

    toml_value(&mut toml, "domain", 42);

    toml_value(&mut toml, "context", 99);

    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("unexpected generator location")
        .join("bin/sod/ecdsa_p256_sha256_ec512/Prover.toml");

    std::fs::write(&path, toml).expect("cannot write the witness");

    println!("wrote {}", path.display());
}

/// A complete document signed with RSA, which is what most states use. The
/// same structures as the elliptic curve documents, so the only thing that
/// differs downstream is the signature check.
fn emit_rsa_document(body: &mut String, work_dir: &scratch::Scratch) {
    let key = rsa::generate(&work_dir.join("dsc-rsa.pem"));

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

    let signature = rsa::sign_sha256(&key, &signed_attrs.bytes);

    writeln!(
        body,
        "// TD3 document signed with an RSA-2048 Document Signer key, with the"
    )
    .unwrap();

    writeln!(
        body,
        "// Barrett reduction parameter the bignum backend takes alongside a modulus."
    )
    .unwrap();

    emit_bytes(body, "RSA_DG1", &dg1, DG1_BUFFER);

    emit_u32(body, "RSA_DG1_LEN", dg1.len());

    emit_bytes(
        body,
        "RSA_ECONTENT",
        &security_object.econtent,
        ECONTENT_BUFFER,
    );

    emit_u32(body, "RSA_ECONTENT_LEN", security_object.econtent.len());

    emit_u32(body, "RSA_OID_OFFSET", security_object.oid_offset);

    for (number, offset) in &security_object.dg_offsets {
        emit_u32(body, &format!("RSA_DG{number}_OFFSET"), *offset);
    }

    emit_bytes(
        body,
        "RSA_SIGNED_ATTRS",
        &signed_attrs.bytes,
        SIGNED_ATTRS_BUFFER,
    );

    emit_u32(body, "RSA_SIGNED_ATTRS_LEN", signed_attrs.bytes.len());

    emit_u32(body, "RSA_DIGEST_OFFSET", signed_attrs.digest_offset);

    emit_bytes(body, "RSA_DIGEST", &ec::sha256(&signed_attrs.bytes), 32);

    emit_limbs(body, "RSA_MODULUS_LIMBS", &key.modulus_limbs());

    emit_limbs(body, "RSA_REDC_LIMBS", &key.redc_limbs());

    emit_limbs(body, "RSA_SIGNATURE_LIMBS", &signature);

    emit_rsa_size_document(body, work_dir, rsa::RSA3072, "RSA3072", "RSA-3072");

    emit_wide_rsa_document(body, work_dir);

    emit_p384_document(body, work_dir);

    emit_curve_document(
        body,
        work_dir,
        &ec::BRAINPOOL_P384R1,
        "BRAINPOOL384",
        "brainpoolP384r1",
    );
}

/// The same document over P-384, the wider curve Doc 9303 permits. Its
/// coordinates and signature components are 48 bytes rather than 32, so
/// every buffer widens with the curve.
fn emit_p384_document(body: &mut String, work_dir: &scratch::Scratch) {
    emit_curve_document(body, work_dir, &ec::P384, "P384", "P-384");
}

/// A document signed with one elliptic curve, under one constant prefix.
fn emit_curve_document(
    body: &mut String,
    work_dir: &scratch::Scratch,
    curve: &'static ec::Curve,
    prefix: &str,
    description: &str,
) {
    let key = ec::generate(curve, &work_dir.join(&format!("dsc-{prefix}.pem")));

    let dg1 = icao::build_dg1(icao::MRZ_TD3);

    let groups = vec![
        icao::DataGroup {
            number: 1,
            content: dg1,
        },
        icao::DataGroup {
            number: 2,
            content: vec![0x5a; 96],
        },
    ];

    let security_object = icao::build_security_object(&groups);

    let signed_attrs = icao::build_signed_attributes(&security_object.econtent);

    let signature = ec::sign_sha256(&key, &signed_attrs.bytes);

    writeln!(
        body,
        "// The same TD3 document signed with a {description} Document Signer key."
    )
    .unwrap();

    emit_bytes(
        body,
        &format!("{prefix}_ECONTENT"),
        &security_object.econtent,
        ECONTENT_BUFFER,
    );

    emit_u32(
        body,
        &format!("{prefix}_ECONTENT_LEN"),
        security_object.econtent.len(),
    );

    emit_bytes(
        body,
        &format!("{prefix}_SIGNED_ATTRS"),
        &signed_attrs.bytes,
        SIGNED_ATTRS_BUFFER,
    );

    emit_u32(
        body,
        &format!("{prefix}_SIGNED_ATTRS_LEN"),
        signed_attrs.bytes.len(),
    );

    emit_u32(
        body,
        &format!("{prefix}_DIGEST_OFFSET"),
        signed_attrs.digest_offset,
    );

    for (number, offset) in &security_object.dg_offsets {
        emit_u32(body, &format!("{prefix}_DG{number}_OFFSET"), *offset);
    }

    emit_bytes(body, &format!("{prefix}_DSC_PUBKEY_X"), &key.public_x, 48);

    emit_bytes(body, &format!("{prefix}_DSC_PUBKEY_Y"), &key.public_y, 48);

    emit_bytes(body, &format!("{prefix}_SIGNATURE_R"), &signature.r, 48);

    emit_bytes(body, &format!("{prefix}_SIGNATURE_S"), &signature.s, 48);
}

/// The same document signed with a 4096 bit key. States do sign with wider
/// keys than 2048, and every derived value widens with the modulus, so the
/// fixture carries both rather than assuming one size fits.
fn emit_wide_rsa_document(body: &mut String, work_dir: &scratch::Scratch) {
    emit_rsa_size_document(body, work_dir, rsa::RSA4096, "RSA4096", "RSA-4096");
}

/// A document signed at one modulus size, under one constant prefix. Every
/// derived value widens with the modulus: the limbs, the Barrett parameter
/// and the signature.
fn emit_rsa_size_document(
    body: &mut String,
    work_dir: &scratch::Scratch,
    size: rsa::Size,
    prefix: &str,
    description: &str,
) {
    let key = rsa::generate_sized(&work_dir.join(&format!("dsc-{prefix}.pem")), size);

    let dg1 = icao::build_dg1(icao::MRZ_TD3);

    let groups = vec![
        icao::DataGroup {
            number: 1,
            content: dg1,
        },
        icao::DataGroup {
            number: 2,
            content: vec![0x5a; 96],
        },
    ];

    let security_object = icao::build_security_object(&groups);

    let signed_attrs = icao::build_signed_attributes(&security_object.econtent);

    let signature = rsa::sign_sha256(&key, &signed_attrs.bytes);

    writeln!(
        body,
        "// The same TD3 document signed with an {description} Document Signer key."
    )
    .unwrap();

    emit_bytes(
        body,
        &format!("{prefix}_ECONTENT"),
        &security_object.econtent,
        ECONTENT_BUFFER,
    );

    emit_u32(
        body,
        &format!("{prefix}_ECONTENT_LEN"),
        security_object.econtent.len(),
    );

    emit_bytes(
        body,
        &format!("{prefix}_SIGNED_ATTRS"),
        &signed_attrs.bytes,
        SIGNED_ATTRS_BUFFER,
    );

    emit_u32(
        body,
        &format!("{prefix}_SIGNED_ATTRS_LEN"),
        signed_attrs.bytes.len(),
    );

    emit_u32(
        body,
        &format!("{prefix}_DIGEST_OFFSET"),
        signed_attrs.digest_offset,
    );

    for (number, offset) in &security_object.dg_offsets {
        emit_u32(body, &format!("{prefix}_DG{number}_OFFSET"), *offset);
    }

    emit_limbs(
        body,
        &format!("{prefix}_MODULUS_LIMBS"),
        &key.modulus_limbs(),
    );

    emit_limbs(body, &format!("{prefix}_REDC_LIMBS"), &key.redc_limbs());

    emit_limbs(body, &format!("{prefix}_SIGNATURE_LIMBS"), &signature);
}

/// A country signing key over a Document Signer certificate, which is the
/// link a trust chain has to check.
fn emit_certificate_chain(body: &mut String, work_dir: &scratch::Scratch) {
    let signer = ec::generate(&ec::P256, &work_dir.join("chain-dsc.pem"));

    let authority = rsa::generate(&work_dir.join("chain-csca.pem"));

    let certificate = cert::build_dsc_tbs(
        &signer.public_x,
        &signer.public_y,
        "170101000000Z",
        "301231235959Z",
    );

    let signature = rsa::sign_sha256(&authority, &certificate.tbs);

    writeln!(
        body,
        "// A Document Signer certificate signed by an RSA-2048 country signing key."
    )
    .unwrap();

    emit_bytes(body, "CHAIN_TBS", &certificate.tbs, CERTIFICATE_BUFFER);

    emit_u32(body, "CHAIN_TBS_LEN", certificate.tbs.len());

    emit_u32(
        body,
        "CHAIN_PUBLIC_KEY_OFFSET",
        certificate.public_key_offset,
    );

    emit_u32(
        body,
        "CHAIN_NOT_BEFORE_OFFSET",
        certificate.not_before_offset,
    );

    emit_u32(body, "CHAIN_NOT_AFTER_OFFSET", certificate.not_after_offset);

    emit_bytes(body, "CHAIN_DSC_PUBKEY_X", &signer.public_x, 32);

    emit_bytes(body, "CHAIN_DSC_PUBKEY_Y", &signer.public_y, 32);

    emit_limbs(body, "CHAIN_CSCA_MODULUS_LIMBS", &authority.modulus_limbs());

    emit_limbs(body, "CHAIN_CSCA_REDC_LIMBS", &authority.redc_limbs());

    emit_limbs(body, "CHAIN_CSCA_SIGNATURE_LIMBS", &signature);
}

fn emit_limbs(body: &mut String, name: &str, value: &[u128]) {
    write!(body, "pub global {name}: [u128; {}] = [", value.len()).unwrap();

    for limb in value {
        write!(body, "\n    {limb},").unwrap();
    }

    body.push_str("\n];\n\n");
}

fn toml_bytes(out: &mut String, name: &str, value: &[u8], width: usize) {
    write!(out, "{name} = [").unwrap();

    for index in 0..width {
        let byte = if index < value.len() { value[index] } else { 0 };

        write!(out, "\"{byte}\", ").unwrap();
    }

    out.push_str("]\n");
}

fn toml_value(out: &mut String, name: &str, value: usize) {
    writeln!(out, "{name} = \"{value}\"").unwrap();
}

fn emit_bytes(body: &mut String, name: &str, value: &[u8], width: usize) {
    assert!(
        value.len() <= width,
        "{name} needs {} bytes but the buffer is {width}",
        value.len()
    );

    write!(body, "pub global {name}: [u8; {width}] = [").unwrap();

    for index in 0..width {
        if index % 16 == 0 {
            body.push_str("\n    ");
        }

        let byte = if index < value.len() { value[index] } else { 0 };

        write!(body, "0x{byte:02x}, ").unwrap();
    }

    body.push_str("\n];\n\n");
}

fn emit_u32(body: &mut String, name: &str, value: usize) {
    writeln!(body, "pub global {name}: u32 = {value};\n").unwrap();
}

const HEADER: &str = "\
//! Generated by fixtures/generator. Do not edit by hand.
//!
//! Synthetic ICAO Doc 9303 documents: a generated Document Signer key over a
//! Security Object covering DG1 and DG2, with the specimen machine readable
//! zones from the standard. Signature s values are normalized to at most n/2,
//! which the circuits require and certificate signatures do not guarantee.

";

/// The chip's own key pair, in DG15, with a signature over a challenge.
///
/// This is what tells a genuine chip from a copy of its data: the private
/// half never leaves the chip, so a copy cannot answer a challenge the
/// verifier chose. The challenge here is a session context, which is what
/// the verifier issues per exchange anyway.
fn emit_chip_key(body: &mut String, work_dir: &scratch::Scratch) {
    let key = ec::generate(&ec::P256, &work_dir.join("chip.pem"));

    let spki = cert::subject_public_key_info(&key.public_x, &key.public_y);

    let dg15 = icao::build_dg15(&spki);

    // The key sits at its offset inside the SubjectPublicKeyInfo, which
    // itself sits after DG15's own two byte template header.
    let key_offset = 2 + cert::public_key_offset_in_spki(&spki);

    // The challenge is the session context as a 32 byte big endian value. A
    // real terminal draws one fresh per read; the circuit requires it to
    // equal the context the verifier published, which is the same thing.
    let mut challenge = [0u8; 32];

    challenge[31] = 99;

    // The chip signs a digest of the challenge, which is what an elliptic
    // curve signing interface does and what the circuit recomputes.
    let signature = ec::sign_sha256(&key, &challenge);

    writeln!(
        body,
        "// The chip's Active Authentication key in DG15, and its answer to a"
    )
    .unwrap();

    writeln!(
        body,
        "// challenge, which a copy of the data could not produce."
    )
    .unwrap();

    emit_bytes(body, "DG15", &dg15, 128);

    emit_u32(body, "DG15_LEN", dg15.len());

    emit_u32(body, "DG15_KEY_OFFSET", key_offset);

    emit_bytes(body, "DG15_CHALLENGE", &challenge, 32);

    emit_bytes(body, "DG15_SIGNATURE_R", &signature.r, 32);

    emit_bytes(body, "DG15_SIGNATURE_S", &signature.s, 32);
}
