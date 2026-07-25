//! Writes the public input layout the off-chain verifier reads.
//!
//! Circuit signatures live here and the verifier lives in another
//! repository, so nothing but this file tells it where `domain` sits or
//! which return value is a commitment. It is generated from the compiled
//! ABIs and committed there, and its tests fail when the two disagree.
//!
//! Two things it must not do. It must not read whatever happens to be in the
//! build directory, because a stale artifact from a deleted package produces
//! an entry for a circuit that no longer exists. And it must not omit the
//! witness tools silently: they are executed and never proved, so no
//! verifier reads their inputs, and the file says so rather than leaving
//! their absence to be noticed.

use std::fmt::Write as _;
use std::path::Path;

/// Packages that solve a witness and are never proved.
const TOOLS: &[&str] = &["mrz_opening", "registry_witness", "document_secret"];

pub fn write(circuits_root: &Path, destination: &Path) {
    let members = workspace_members(circuits_root);

    let mut body = String::from(
        "# Public input order per circuit, generated from the compiled ABIs.\n\
         # Each name is one field element, in the order Barretenberg lays them out.\n\
         # Witness tools are excluded: they are executed, never proved, so no\n\
         # verifier reads their public inputs.\n",
    );

    let mut written = 0;

    for member in &members {
        let manifest = circuits_root.join(member).join("Nargo.toml");

        // Only circuits have public inputs. Libraries compile into the
        // circuits that use them and produce no bytecode of their own.
        if package_field(&manifest, "type") != "bin" {
            continue;
        }

        let package = package_field(&manifest, "name");

        if TOOLS.contains(&package.as_str()) {
            continue;
        }

        let bytecode = circuits_root.join(format!("target/{package}.json"));

        assert!(
            bytecode.exists(),
            "{package} is a workspace member but has not been compiled; run nargo compile first"
        );

        writeln!(body, "{package} {}", public_inputs(&bytecode)).unwrap();

        written += 1;
    }

    assert!(written > 0, "the workspace declares no circuits");

    std::fs::write(destination, body).expect("cannot write the manifest");

    println!("wrote {} with {written} circuits", destination.display());
}

/// Only packages the workspace declares. Reading the build directory instead
/// would carry forward anything left behind by a package that has been
/// removed.
fn workspace_members(circuits_root: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(circuits_root.join("Nargo.toml"))
        .expect("cannot read the workspace manifest");

    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('"'))
        .map(|line| line.trim_matches(|c| c == '"' || c == ',').to_string())
        .filter(|member| !member.is_empty())
        .collect()
}

fn package_field(manifest: &Path, field: &str) -> String {
    let text = std::fs::read_to_string(manifest)
        .unwrap_or_else(|_| panic!("cannot read {}", manifest.display()));

    let key = format!("{field} = ");

    text.lines()
        .find_map(|line| line.trim().strip_prefix(&key))
        .map(|value| value.trim_matches('"').to_string())
        .unwrap_or_else(|| panic!("{} declares no {field}", manifest.display()))
}

/// Walks the ABI in the order Barretenberg lays public inputs out: public
/// parameters as declared, then the return values.
fn public_inputs(bytecode: &Path) -> String {
    let text = std::fs::read_to_string(bytecode).expect("cannot read compiled bytecode");

    let abi = json::section(&text, "\"abi\":").expect("compiled output has no abi");

    let mut names = Vec::new();

    for parameter in
        json::array_items(&json::field(&abi, "parameters").expect("abi has no parameters"))
    {
        if json::string(&parameter, "visibility").as_deref() != Some("public") {
            continue;
        }

        let name = json::string(&parameter, "name").expect("a parameter has no name");

        let slots =
            json::slot_count(&json::field(&parameter, "type").expect("a parameter has no type"));

        if slots == 1 {
            names.push(name);
        } else {
            for index in 0..slots {
                names.push(format!("{name}[{index}]"));
            }
        }
    }

    // A circuit that only asserts returns nothing, which the ABI records as
    // a null rather than by leaving the field out.
    if let Some(return_type) = json::field(&abi, "return_type") {
        if return_type.trim() != "null" {
            let inner =
                json::field(&return_type, "abi_type").expect("a return type has no abi_type");

            for index in 0..json::slot_count(&inner) {
                names.push(format!("return[{index}]"));
            }
        }
    }

    names.join(" ")
}

/// A reader for the shapes this one file needs, rather than a general JSON
/// parser. It is enough to walk an ABI and nothing more.
mod json {
    /// The balanced brace or bracket run that follows `key`.
    pub fn section(text: &str, key: &str) -> Option<String> {
        let start = text.find(key)? + key.len();

        balanced(&text[start..])
    }

    pub fn field(object: &str, name: &str) -> Option<String> {
        let key = format!("\"{name}\":");

        let mut depth = 0;

        let bytes = object.as_bytes();

        for index in 0..bytes.len() {
            match bytes[index] {
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                _ => {}
            }

            // Only fields of this object, not of anything nested in it.
            if depth == 1 && object[index..].starts_with(&key) {
                return balanced(&object[index + key.len()..]);
            }
        }

        None
    }

    pub fn string(object: &str, name: &str) -> Option<String> {
        let raw = field(object, name)?;

        let trimmed = raw.trim();

        trimmed
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_string)
    }

    pub fn array_items(array: &str) -> Vec<String> {
        let inner = array.trim();

        let inner = inner
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(inner);

        let mut items = Vec::new();

        let mut depth = 0;

        let mut start = 0;

        let bytes = inner.as_bytes();

        for index in 0..bytes.len() {
            match bytes[index] {
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                b',' if depth == 0 => {
                    items.push(inner[start..index].to_string());

                    start = index + 1;
                }
                _ => {}
            }
        }

        if !inner[start..].trim().is_empty() {
            items.push(inner[start..].to_string());
        }

        items
    }

    /// How many field elements a type occupies in the public inputs.
    pub fn slot_count(abi_type: &str) -> usize {
        match string(abi_type, "kind").as_deref() {
            Some("field") | Some("integer") | Some("boolean") | Some("string") => 1,
            Some("array") => {
                let length: usize = field(abi_type, "length")
                    .and_then(|value| value.trim().parse().ok())
                    .expect("an array type has no length");

                length * slot_count(&field(abi_type, "type").expect("an array has no element type"))
            }
            Some("tuple") => {
                array_items(&field(abi_type, "fields").expect("a tuple has no fields"))
                    .iter()
                    .map(|item| slot_count(item))
                    .sum()
            }
            Some("struct") => {
                array_items(&field(abi_type, "fields").expect("a struct has no fields"))
                    .iter()
                    .map(|item| {
                        slot_count(&field(item, "type").expect("a struct field has no type"))
                    })
                    .sum()
            }
            other => panic!("unhandled abi type kind {other:?}"),
        }
    }

    fn balanced(text: &str) -> Option<String> {
        let trimmed = text.trim_start();

        let offset = text.len() - trimmed.len();

        let open = trimmed.chars().next()?;

        let close = match open {
            '{' => '}',
            '[' => ']',
            _ => {
                // A scalar: read to the next separator at this level.
                let end = trimmed
                    .find(|c| c == ',' || c == '}' || c == ']')
                    .unwrap_or(trimmed.len());

                return Some(text[offset..offset + end].trim().to_string());
            }
        };

        let mut depth = 0;

        for (index, character) in trimmed.char_indices() {
            if character == open {
                depth += 1;
            } else if character == close {
                depth -= 1;

                if depth == 0 {
                    return Some(trimmed[..=index].to_string());
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::json;

    const SAMPLE: &str = r#"{"abi":{"parameters":[{"name":"econtent","type":{"kind":"array","length":512,"type":{"kind":"integer"}},"visibility":"private"},{"name":"domain","type":{"kind":"field"},"visibility":"public"},{"name":"context","type":{"kind":"field"},"visibility":"public"}],"return_type":{"abi_type":{"kind":"tuple","fields":[{"kind":"field"},{"kind":"field"}]},"visibility":"public"}}}"#;

    #[test]
    fn reads_a_nested_section() {
        let abi = json::section(SAMPLE, "\"abi\":").unwrap();

        assert!(abi.starts_with('{'));

        assert!(abi.contains("parameters"));
    }

    #[test]
    fn reads_only_fields_of_the_object_itself() {
        let abi = json::section(SAMPLE, "\"abi\":").unwrap();

        let parameters = json::field(&abi, "parameters").unwrap();

        assert_eq!(json::array_items(&parameters).len(), 3);
    }

    #[test]
    fn counts_slots_for_every_shape() {
        assert_eq!(json::slot_count(r#"{"kind":"field"}"#), 1);

        assert_eq!(
            json::slot_count(r#"{"kind":"array","length":4,"type":{"kind":"field"}}"#),
            4
        );

        assert_eq!(
            json::slot_count(r#"{"kind":"tuple","fields":[{"kind":"field"},{"kind":"field"}]}"#),
            2
        );
    }

    // predicate_compare and its siblings only assert, so their ABI records a
    // null return. Treating that as a value shape panicked.
    #[test]
    fn a_null_return_type_is_read_as_no_return() {
        let assert_only = r#"{"abi":{"parameters":[{"name":"domain","type":{"kind":"field"},"visibility":"public"}],"return_type":null}}"#;

        let abi = json::section(assert_only, "\"abi\":").unwrap();

        assert_eq!(json::field(&abi, "return_type").unwrap().trim(), "null");
    }

    #[test]
    fn an_array_of_arrays_counts_every_element() {
        let nested = r#"{"kind":"array","length":2,"type":{"kind":"array","length":3,"type":{"kind":"field"}}}"#;

        assert_eq!(json::slot_count(nested), 6);
    }
}
