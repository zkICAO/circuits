//! Tells the linker where the rapidsnark library is, when it is asked for.
//!
//! rapidsnark is not on crates.io: it is C++ built for the host, so its
//! location is the builder's to say rather than something this crate can
//! assume. Nothing is downloaded or built here.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=RAPIDSNARK_LIB");

    if std::env::var("CARGO_FEATURE_RAPIDSNARK").is_err() {
        return;
    }

    let Ok(directory) = std::env::var("RAPIDSNARK_LIB") else {
        panic!(
            "the rapidsnark feature is on but RAPIDSNARK_LIB is unset. \
             Build rapidsnark for this host and point it at the lib directory; \
             see the feature comment in Cargo.toml."
        );
    };

    let out = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");

    // rapidsnark installs a dynamic library beside each archive, and a
    // linker given a search path containing both takes the dynamic one,
    // whatever it was asked for. The archives are copied somewhere the
    // dynamic ones are not, so there is nothing else to find: a binary that
    // resolved the prover at run time would be looking for a library the
    // deployment never shipped.
    let libraries = ["rapidsnark", "fr", "fq", "gmp"];

    for library in libraries {
        let archive = Path::new(&directory).join(format!("lib{library}.a"));

        if !archive.exists() {
            panic!(
                "{} is missing; build rapidsnark for this host first",
                archive.display()
            );
        }

        std::fs::copy(&archive, Path::new(&out).join(format!("lib{library}.a")))
            .unwrap_or_else(|e| panic!("cannot stage {}: {e}", archive.display()));

        println!("cargo:rustc-link-lib=static={library}");
    }

    println!("cargo:rustc-link-search=native={out}");

    println!("cargo:rustc-link-lib=c++");
}
