//! Writes every default email-signup template with sample data to
//! `target/previews/*.{html,txt}` (issue #12). Host-only tooling: the
//! module library itself never touches `std::fs`.
//!
//! ```text
//! cargo run -p factory0-module-email-signup --example render-preview
//! ```

use factory0_core::Brand;
use factory0_module_email_signup::{ConfirmMailData, WelcomeMailData, default_templates};
use serde_json::json;

fn main() {
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/previews");
    std::fs::create_dir_all(&out).expect("create target/previews");

    let brand = Brand {
        accent: "#FF5A36".to_owned(),
        logo_url: Some("https://factory0.ventures/logo.png".to_owned()),
        footer: Some("Factory Zero · factory0.ventures".to_owned()),
    };
    let confirm = json!(ConfirmMailData {
        venture: "factory0".to_owned(),
        email: "nick@example.com".to_owned(),
        confirm_url: "https://api.factory0.ventures/v1/email-signup/confirm?token=sample"
            .to_owned(),
        unsubscribe_url: "https://api.factory0.ventures/v1/email-signup/unsubscribe?token=sample"
            .to_owned(),
        brand: brand.clone(),
    });
    let welcome = json!(WelcomeMailData {
        venture: "factory0".to_owned(),
        email: "nick@example.com".to_owned(),
        unsubscribe_url: "https://api.factory0.ventures/v1/email-signup/unsubscribe?token=sample"
            .to_owned(),
        brand,
    });

    for (id, data) in [
        ("email-signup/confirm", &confirm),
        ("email-signup/welcome", &welcome),
    ] {
        let template = default_templates()
            .into_iter()
            .find(|(template_id, _)| template_id == id)
            .unwrap_or_else(|| panic!("{id} in default templates"))
            .1;
        let rendered = template
            .render(data, "en")
            .unwrap_or_else(|err| panic!("{id} renders: {err}"));
        let stem = id.replace('/', "_");
        for (ext, body) in [("html", &rendered.html), ("txt", &rendered.text)] {
            let path = out.join(format!("{stem}.{ext}"));
            std::fs::write(&path, body.as_bytes()).expect("write preview");
            println!("wrote {}", path.display());
        }
    }
}
