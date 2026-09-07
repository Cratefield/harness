//! `LocalFileKms` against the port's conformance suite, plus the two
//! behaviours that are specific to it: the production refusal and the
//! key-file formats (issue #40).

use std::fmt::Write as _;

use factory0_kms::{Dek, Kms, KmsError, LocalFileKms, conformance};

/// The hex encoding a key file may carry.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fz_kms_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dev_kms(scratch: &Scratch, name: &str) -> LocalFileKms {
    let path = scratch.path(name);
    LocalFileKms::create(&path).expect("writes a key");
    LocalFileKms::open(&path, "development").expect("opens it")
}

#[pollster::test]
async fn local_file_passes_the_port_conformance() {
    let scratch = Scratch::new("conformance");
    let kms = dev_kms(&scratch, "kek");
    assert_eq!(kms.provider(), "local-file");
    conformance(&kms).await;
}

#[test]
fn it_refuses_production_however_it_is_constructed() {
    let scratch = Scratch::new("prod");
    let path = scratch.path("kek");
    LocalFileKms::create(&path).expect("writes a key");

    for env in ["production", "PRODUCTION", "Production"] {
        let err = LocalFileKms::open(&path, env).expect_err("must refuse production");
        assert!(matches!(err, KmsError::Refused(_)), "{err}");
        assert!(err.to_string().contains("managed KMS") || err.to_string().contains("development"));
        assert!(!err.is_retryable(), "a refusal is not something to retry");

        let key = Dek::generate().expect("rng");
        assert!(
            matches!(
                LocalFileKms::from_key(key, "in-memory", env),
                Err(KmsError::Refused(_))
            ),
            "the in-memory constructor refuses production too"
        );
    }
    // Every other environment is fine.
    for env in ["development", "staging", "test"] {
        assert!(LocalFileKms::open(&path, env).is_ok(), "{env}");
    }
}

#[pollster::test]
async fn a_key_file_may_be_raw_hex_or_base64() {
    use base64::Engine as _;
    let scratch = Scratch::new("formats");
    let raw = vec![9_u8; 32];

    let files = [
        ("raw", raw.clone()),
        ("hex", to_hex(&raw).into_bytes()),
        ("hex_newline", format!("{}\n", to_hex(&raw)).into_bytes()),
        (
            "base64",
            base64::engine::general_purpose::STANDARD
                .encode(&raw)
                .into_bytes(),
        ),
    ];
    let mut wrapped_by = Vec::new();
    for (name, body) in files {
        let path = scratch.path(name);
        std::fs::write(&path, body).expect("write");
        let kms = LocalFileKms::open(&path, "development")
            .unwrap_or_else(|err| panic!("{name} should open: {err}"));
        let dek = Dek::generate().expect("rng");
        wrapped_by.push((kms.wrap(&dek).await.expect("wrap"), dek));
    }
    // All four encode the same key, so any of them unwraps the others'.
    let first = LocalFileKms::open(scratch.path("raw"), "development").expect("open");
    for (wrapped, dek) in &wrapped_by {
        let out = first.unwrap(wrapped).await.expect("same key, same unwrap");
        assert_eq!(out.expose(), dek.expose());
    }
}

#[test]
fn a_file_that_is_not_a_key_is_refused_clearly() {
    let scratch = Scratch::new("bad");
    for (name, body) in [
        ("short", "abc"),
        ("empty", ""),
        ("prose", "not a key at all"),
    ] {
        let path = scratch.path(name);
        std::fs::write(&path, body).expect("write");
        let err = LocalFileKms::open(&path, "development").expect_err(name);
        assert!(matches!(err, KmsError::Invalid(_)), "{name}: {err}");
        assert!(err.to_string().contains("32-byte key"), "{err}");
    }
    let err = LocalFileKms::open(scratch.path("absent"), "development").expect_err("missing file");
    assert!(matches!(err, KmsError::Unavailable(_)), "{err}");
    assert!(
        err.is_retryable(),
        "a missing file may be a mount that is late"
    );
}

#[test]
fn create_never_overwrites_an_existing_key() {
    let scratch = Scratch::new("create");
    let path = scratch.path("kek");
    LocalFileKms::create(&path).expect("first write");
    let before = std::fs::read(&path).expect("read");
    let err = LocalFileKms::create(&path).expect_err("must refuse to overwrite");
    assert!(matches!(err, KmsError::Refused(_)), "{err}");
    assert_eq!(
        before,
        std::fs::read(&path).expect("read"),
        "the existing key is untouched"
    );
}

/// A key wrapped under one master key must not unwrap under another.
#[pollster::test]
async fn a_wrapped_key_is_bound_to_its_master_key() {
    let scratch = Scratch::new("binding");
    let one = dev_kms(&scratch, "kek_one");
    let two = dev_kms(&scratch, "kek_two");
    let dek = Dek::generate().expect("rng");
    let wrapped = one.wrap(&dek).await.expect("wrap");

    let err = two
        .unwrap(&wrapped)
        .await
        .expect_err("a different KEK must fail");
    assert!(matches!(err, KmsError::Tampered(_)), "{err}");
    assert!(
        !err.is_retryable(),
        "retrying under the wrong key never helps"
    );
}
