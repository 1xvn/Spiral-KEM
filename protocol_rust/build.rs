use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = root.join("../native_research/spiral_native.c");
    let header = root.join("../native_research/spiral_native.h");
    for (path, expected) in [
        (
            &source,
            "ccb29fe8b1f428c25a93c8cb967f1090eea619ad36dcba7d53dc9bfaedc1cd0f",
        ),
        (
            &header,
            "85f0454ee626cc0c38cdd6b60b12453f90276b6681dd91ab634d48c20bb1597b",
        ),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(path).unwrap())),
            expected,
            "native profile differs from the reviewed source"
        );
    }
    cc::Build::new()
        .file(source)
        .include(header.parent().unwrap())
        .flag_if_supported("-std=c11")
        .flag_if_supported("-fvisibility=hidden")
        .warnings(true)
        .warnings_into_errors(true)
        .opt_level(2)
        .compile("spiral_native");
    println!("cargo:rustc-link-lib=crypto");
}
