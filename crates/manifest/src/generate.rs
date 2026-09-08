//! The deterministic Rust composition generator (issue #138).
//!
//! Given a resolved [`ModuleSet`](crate::catalog::ModuleSet) and a
//! [`VentureManifest`](crate::VentureManifest), emit the source of a
//! complete Cloudflare venture crate — `Cargo.toml`, `src/lib.rs`,
//! `src/fz_main.rs`, `wrangler.toml`, and (if present) `seed.sql`. The
//! output is a pure function of the inputs: the same manifest always
//! generates byte-identical files, so the artifact key (harness ADR 0009)
//! is stable and a build is reproducible.
//!
//! This crate stops at *source*. Turning the generated crate into a
//! deployable wasm is `worker-build` (the CLI's `fz build` prints that as
//! the next step); running it needs a toolchain, which is exactly what the
//! desktop app and the Docker image package.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::catalog::ModuleSet;
use crate::manifest::VentureManifest;

/// How the generated `Cargo.toml` should reference the `cratefield` facade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessSource {
    /// A published version, e.g. `cratefield = { version = "0.1", ... }`.
    /// The default for a manifest that promotes to Cloudflare.
    Version(String),
    /// A local path to the harness workspace root, for offline / in-repo
    /// builds (the Docker image and dev use this). The facade is at
    /// `{base}/crates/facade`.
    Path(String),
}

impl Default for HarnessSource {
    fn default() -> Self {
        HarnessSource::Version("0.1".to_owned())
    }
}

/// Codegen facts about one module: how the facade exposes it and what the
/// composition must wire for it. This is the one place a new module is
/// taught to the generator.
struct ModuleCodegen {
    slug: &'static str,
    /// The `cratefield` facade feature that pulls the module in.
    feature: &'static str,
    /// The facade submodule the type lives under (`cratefield::{module}`).
    module: &'static str,
    /// The module's constructor type.
    type_name: &'static str,
    /// The module ships `default_templates()` to register.
    has_templates: bool,
    /// The module requires the `Mailer` port, so the runtime must provide
    /// one (the generator wires a not-configured Resend, like the example
    /// venture: the port exists, nothing is sent until a key is set).
    needs_mailer: bool,
}

const REGISTRY: &[ModuleCodegen] = &[
    ModuleCodegen {
        slug: "email-signup",
        feature: "email-signup",
        module: "email_signup",
        type_name: "EmailSignup",
        has_templates: true,
        needs_mailer: true,
    },
    ModuleCodegen {
        slug: "waitlist",
        feature: "waitlist",
        module: "waitlist",
        type_name: "Waitlist",
        has_templates: true,
        needs_mailer: true,
    },
    ModuleCodegen {
        slug: "cms",
        feature: "cms",
        module: "cms",
        type_name: "Cms",
        has_templates: false,
        needs_mailer: false,
    },
];

fn codegen_for(slug: &str) -> Option<&'static ModuleCodegen> {
    REGISTRY.iter().find(|m| m.slug == slug)
}

/// A generated file: a repo-relative path and its full contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    pub path: String,
    pub contents: String,
}

/// The generated venture crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedVenture {
    /// The venture (crate) name.
    pub name: String,
    /// The resolved module slugs, dependencies first.
    pub modules: Vec<String>,
    /// The artifact key: the module set's content key.
    pub content_key: String,
    /// A sha256 over the generated files, for a reproducible-build check.
    pub composition_hash: String,
    /// Every file to write, in a stable order.
    pub files: Vec<GeneratedFile>,
}

/// Why generation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// A resolved module has no codegen entry (in the catalog but the
    /// generator has not been taught to compose it).
    NotGeneratable(String),
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateError::NotGeneratable(slug) => write!(
                f,
                "module `{slug}` resolves but the composition generator does not know how to \
                 wire it (add it to the codegen registry)"
            ),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Generate the venture crate from a manifest and its resolved module set.
///
/// # Errors
///
/// [`GenerateError::NotGeneratable`] if the module set contains a slug the
/// generator cannot compose.
pub fn generate(
    manifest: &VentureManifest,
    module_set: &ModuleSet,
    source: &HarnessSource,
) -> Result<GeneratedVenture, GenerateError> {
    let modules: Vec<&'static ModuleCodegen> = module_set
        .slugs()
        .iter()
        .map(|slug| codegen_for(slug).ok_or_else(|| GenerateError::NotGeneratable(slug.clone())))
        .collect::<Result<_, _>>()?;

    let needs_mailer = modules.iter().any(|m| m.needs_mailer);

    let mut files = vec![
        GeneratedFile {
            path: "Cargo.toml".to_owned(),
            contents: cargo_toml(manifest, &modules, needs_mailer, source),
        },
        GeneratedFile {
            path: "src/lib.rs".to_owned(),
            contents: lib_rs(manifest, &modules, needs_mailer),
        },
        GeneratedFile {
            path: "src/fz_main.rs".to_owned(),
            contents: fz_main_rs(manifest),
        },
        GeneratedFile {
            path: "wrangler.toml".to_owned(),
            contents: wrangler_toml(manifest),
        },
    ];
    if let Some(seed) = &manifest.seed_sql {
        files.push(GeneratedFile {
            path: "seed.sql".to_owned(),
            contents: ensure_trailing_newline(seed),
        });
    }

    let composition_hash = hash_files(&files);

    Ok(GeneratedVenture {
        name: manifest.name.clone(),
        modules: module_set.slugs().to_vec(),
        content_key: module_set.content_key(),
        composition_hash,
        files,
    })
}

fn crate_ident(name: &str) -> String {
    name.replace('-', "_")
}

fn cargo_toml(
    manifest: &VentureManifest,
    modules: &[&ModuleCodegen],
    needs_mailer: bool,
    source: &HarnessSource,
) -> String {
    // Sorted, de-duplicated feature set for a deterministic manifest.
    let mut features: BTreeSet<&str> = BTreeSet::new();
    features.insert("cloudflare");
    if needs_mailer {
        features.insert("resend");
    }
    for m in modules {
        features.insert(m.feature);
    }
    let mut feature_lines = String::new();
    for feature in &features {
        let _ = writeln!(feature_lines, "    \"{feature}\",");
    }

    let cratefield_dep = match source {
        HarnessSource::Version(version) => {
            format!("cratefield = {{ version = \"{version}\", features = [\n{feature_lines}] }}")
        }
        HarnessSource::Path(base) => format!(
            "cratefield = {{ path = \"{base}/crates/facade\", features = [\n{feature_lines}] }}"
        ),
    };
    // The fz bin links cratefield-cli natively; from a path source it is a
    // path dep, from a version source it is published alongside the facade.
    let cli_dep = match source {
        HarnessSource::Version(version) => {
            format!("cratefield-cli = {{ version = \"{version}\" }}")
        }
        HarnessSource::Path(base) => format!("cratefield-cli = {{ path = \"{base}/crates/cli\" }}"),
    };

    format!(
        "# GENERATED by `fz build` from the venture manifest. Do not edit by\n\
         # hand: re-run `fz build` to regenerate. The module set is\n\
         # `{content_key}`.\n\
         [package]\n\
         name = \"{name}\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\
         publish = false\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\", \"rlib\"]\n\
         \n\
         [[bin]]\n\
         name = \"fz\"\n\
         path = \"src/fz_main.rs\"\n\
         \n\
         [dependencies]\n\
         {cratefield_dep}\n\
         worker = {{ version = \"0.8.5\", default-features = false, features = [\"d1\"] }}\n\
         {cli_dep}\n\
         \n\
         [target.'cfg(target_arch = \"wasm32\")'.dependencies]\n\
         getrandom = {{ version = \"0.4.3\", default-features = false, features = [\"wasm_js\"] }}\n",
        content_key = module_set_key(modules),
        name = manifest.name,
    )
}

fn module_set_key(modules: &[&ModuleCodegen]) -> String {
    let mut slugs: Vec<&str> = modules.iter().map(|m| m.slug).collect();
    slugs.sort_unstable();
    slugs.join("+")
}

#[allow(clippy::too_many_lines)]
fn lib_rs(manifest: &VentureManifest, modules: &[&ModuleCodegen], needs_mailer: bool) -> String {
    let mut out = String::new();
    out.push_str(
        "//! GENERATED by `fz build` from the venture manifest. Do not edit by\n\
         //! hand: re-run `fz build` to regenerate.\n\
         #![forbid(unsafe_code)]\n\n\
         use cratefield::Harness;\n\
         use cratefield::cloudflare::{Cloudflare, serve, serve_scheduled};\n",
    );
    for m in modules {
        let _ = writeln!(
            out,
            "use cratefield::{module}::{ty};",
            module = m.module,
            ty = m.type_name
        );
    }
    out.push_str(
        "use std::sync::OnceLock;\n\
         use worker::{Context, Env, Request, Response, event};\n\n\
         static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();\n\n",
    );

    // The runtime, built the same way in `harness()` (for validation and
    // `fz`) and in `instance()` (for serving).
    let runtime_expr = if needs_mailer {
        "Cloudflare::new().db(\"DB\").mailer(cratefield::resend::Resend::new(\n\
         \x20           std::sync::Arc::new(cratefield::cloudflare::FetchClient),\n\
         \x20           None,\n\
         \x20           \"no-reply@{host}\",\n\
         \x20           None,\n\
         \x20       ))"
    } else {
        "Cloudflare::new().db(\"DB\")"
    };
    let runtime_expr = runtime_expr.replace("{host}", &manifest.host);

    // The shared composition. `build()` takes a runtime for validation and
    // returns the Harness; serving uses a second identical runtime.
    let cors = manifest
        .cors_origins
        .iter()
        .map(|o| format!("\"{o}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let public_url = manifest
        .public_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", manifest.host));

    let _ = write!(
        out,
        "/// The composed venture harness (module set `{key}`).\n\
         #[must_use]\n\
         pub fn harness() -> Harness {{\n\
         \x20   compose().0\n\
         }}\n\n\
         /// The serving runtime for this venture.\n\
         #[must_use]\n\
         pub fn runtime() -> Cloudflare {{\n\
         \x20   {runtime_expr}\n\
         }}\n\n\
         fn compose() -> (Harness, Cloudflare) {{\n",
        key = module_set_key(modules),
    );

    // Templates: start from the first templates module's `default_templates()`
    // and extend with the rest, exactly as the example venture does.
    let template_modules: Vec<&&ModuleCodegen> =
        modules.iter().filter(|m| m.has_templates).collect();
    if let Some((first, rest)) = template_modules.split_first() {
        let _ = writeln!(
            out,
            "    let mut templates = cratefield::{module}::default_templates();",
            module = first.module
        );
        for m in rest {
            let _ = writeln!(
                out,
                "    templates.extend(cratefield::{module}::default_templates());",
                module = m.module
            );
        }
    }

    let _ = write!(
        out,
        "    let harness = Harness::builder()\n\
         \x20       .venture(\n\
         \x20           cratefield::Venture::new(\"{name}\", \"{host}\")\n\
         \x20               .public_url(\"{public_url}\")\n\
         \x20               .cors_origins([{cors}]),\n\
         \x20       )\n",
        name = manifest.name,
        host = manifest.host,
    );
    for m in modules {
        let _ = writeln!(out, "        .module({ty}::new())", ty = m.type_name);
    }
    if modules.iter().any(|m| m.has_templates) {
        out.push_str("        .templates(templates)\n");
    }
    out.push_str(
        "        .runtime(runtime())\n\
         \x20       .build()\n\
         \x20       .expect(\"generated venture harness is valid\");\n\
         \x20   (harness, runtime())\n\
         }\n\n",
    );

    out.push_str(
        "#[event(fetch)]\n\
         /// Worker fetch entry point.\n\
         ///\n\
         /// # Errors\n\
         ///\n\
         /// Propagates `worker::Error` from the harness router.\n\
         pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {\n\
         \x20   let (harness, runtime) = INSTANCE.get_or_init(compose);\n\
         \x20   serve(harness, runtime, req, env, ctx).await\n\
         }\n\n\
         #[event(scheduled)]\n\
         pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {\n\
         \x20   let (harness, runtime) = INSTANCE.get_or_init(compose);\n\
         \x20   serve_scheduled(harness, runtime, event, env, ctx).await;\n\
         }\n",
    );
    out
}

fn fz_main_rs(manifest: &VentureManifest) -> String {
    format!(
        "//! GENERATED by `fz build`. The venture-linked `fz`: it sees the\n\
         //! compiled-in harness, so `fz migrations collect` etc. work here.\n\
         fn main() {{\n\
         \x20   cratefield_cli::main_for({ident}::harness);\n\
         }}\n",
        ident = crate_ident(&manifest.name),
    )
}

fn wrangler_toml(manifest: &VentureManifest) -> String {
    let mut out = format!(
        "# GENERATED by `fz build`. Deploy with `wrangler deploy` after\n\
         # `worker-build` (needs the account's Cloudflare credentials).\n\
         name = \"{name}\"\n\
         main = \"build/worker/shim.mjs\"\n\
         compatibility_date = \"2024-11-01\"\n\
         \n\
         [build]\n\
         command = \"worker-build --release\"\n\
         \n\
         [[d1_databases]]\n\
         binding = \"DB\"\n\
         database_name = \"{name}\"\n\
         migrations_dir = \"migrations\"\n",
        name = manifest.name,
    );
    if !manifest.config.is_empty() {
        out.push_str("\n[vars]\n");
        for (key, value) in &manifest.config {
            let _ = writeln!(out, "{key} = \"{value}\"");
        }
    }
    out
}

fn ensure_trailing_newline(text: &str) -> String {
    if text.ends_with('\n') {
        text.to_owned()
    } else {
        format!("{text}\n")
    }
}

fn hash_files(files: &[GeneratedFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update([0]);
        hasher.update(file.contents.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    digest.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}
