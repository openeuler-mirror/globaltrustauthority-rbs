use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = PathBuf::from(&crate_dir).join("include");
    let out_file = out_dir.join("rbc.h");

    std::fs::create_dir_all(&out_dir).expect("create include dir");

    let config = cbindgen::Config::from_file(PathBuf::from(&crate_dir).join("cbindgen.toml"))
        .expect("read cbindgen.toml");

    match cbindgen::Builder::new().with_crate(&crate_dir).with_config(config).generate() {
        Ok(bindings) => {
            bindings.write_to_file(&out_file);
        },
        Err(e) => {
            panic!("cbindgen failed: {e}");
        },
    }

    // Re-run when source files change.
    println!("cargo:rerun-if-changed=src/ffi/mod.rs");
    println!("cargo:rerun-if-changed=src/ffi/error.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
    // Re-run if the output header is missing (e.g., after `rm include/rbc.h`).
    // Cargo re-runs build.rs whenever a rerun-if-changed path does not exist.
    println!("cargo:rerun-if-changed=include/rbc.h");
}
