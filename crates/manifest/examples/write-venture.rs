//! Writes a generated venture to disk, for the canary under
//! `examples/tables-canary` and for anyone who wants to read one.
//!
//! `fz build` is the command a venture author runs; this is the same
//! generator with an output directory, so the canary can be regenerated
//! and byte-compared by a test.

fn main() {
    let mut args = std::env::args().skip(1);
    let manifest_path = args
        .next()
        .expect("usage: write-venture <manifest> <out-dir>");
    let out = args
        .next()
        .expect("usage: write-venture <manifest> <out-dir>");
    let json = std::fs::read_to_string(&manifest_path).expect("the manifest reads");
    let manifest =
        cratefield_manifest::VentureManifest::from_json_str(&json).expect("the manifest parses");
    let set = manifest
        .resolve(&cratefield_manifest::catalog::builtin())
        .expect("the module set resolves");
    let venture = cratefield_manifest::generate(
        &manifest,
        &set,
        &cratefield_manifest::generate::HarnessSource::Path("../..".into()),
    )
    .expect("it generates");
    for file in &venture.files {
        let path = std::path::Path::new(&out).join(&file.path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the directory is made");
        std::fs::write(&path, &file.contents).expect("the file is written");
        println!("{}", file.path);
    }
}
