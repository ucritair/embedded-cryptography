fn main() {
    let opt_level = std::env::var_os("OPT_LEVEL").unwrap();
    println!("cargo::rustc-env=G_OPT_LVEL={}", opt_level.display());

    println!("cargo::rustc-env=G_TESTING=MEOW");


    // Ensure Cargo reruns this script when inputs change
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    // Generate C header with cbindgen into include/battery.h
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::path::Path::new(&crate_dir).join("include");
    std::fs::create_dir_all(&out_dir).unwrap();
    let header_path = out_dir.join("battery.h");

    match cbindgen::generate(&crate_dir) {
        Ok(builder) => {
            builder.write_to_file(header_path);
        }
        Err(err) => {
            // Fail the build if header generation fails to avoid stale headers.
            panic!("cbindgen generate failed: {}", err);
        }
    }
}
