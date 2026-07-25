//! Generates synthetic ICAO Doc 9303 test vectors and writes them out as a
//! Noir library, so circuit tests run against a complete signed document
//! without reading files at proving time.
//!
//! The documents are synthetic: keys are generated here and the specimen
//! machine readable zones are the ones Doc 9303 publishes as examples. No
//! genuine document is involved, and regenerating produces a fresh key, so
//! the committed output is the fixture of record.

mod bigint;
mod cert;
mod der;
mod ec;
mod icao;
mod rsa;

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
    let out_path = target_path();

    let work_dir = std::env::temp_dir().join("zkicao-fixtures");

    std::fs::create_dir_all(&work_dir).expect("cannot create working directory");

    let documents = [
        Document {
            prefix: "TD3",
            mrz: icao::MRZ_TD3,
            mrz_len: 88,
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

        let key = ec::generate(&ec::P256, &work_dir.join(format!("dsc{index}.pem")));

        emit_document(&mut body, document, &key);

        if index == 0 {
            emit_prover_toml(document, &key);
        }
    }

    emit_rsa_document(&mut body, &work_dir);

    emit_certificate_chain(&mut body, &work_dir);

    std::fs::write(&out_path, body).expect("cannot write the fixture library");

    std::fs::remove_dir_all(&work_dir).ok();

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
fn emit_rsa_document(body: &mut String, work_dir: &Path) {
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
}

/// A country signing key over a Document Signer certificate, which is the
/// link a trust chain has to check.
fn emit_certificate_chain(body: &mut String, work_dir: &Path) {
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
