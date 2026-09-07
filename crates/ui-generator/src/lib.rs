//! Brief to `UiSpec` (issue #9): a venture's look from a sentence.
//!
//! Once a venture is provisioned it has an API and a bare set of `/ui` pages.
//! This turns a one-line brief ("make it feel like a record label site") plus
//! the venture's own [`SurfaceDocument`] (from `GET /__surface`) into a
//! validated [`UiSpec`] — the runtime configuration that themes those pages
//! with no rebuild.
//!
//! **It cannot invent.** The generator only ever names modules and actions
//! that the surface declares, and it sets no field, route or landing page the
//! surface does not have. The guarantee is not merely by construction: every
//! spec is run through [`UiSpec::validate`] against the surface (the harness's
//! own check, which rejects any reference to something the surface does not
//! declare). A spec that does not validate is regenerated as theme-only —
//! which references nothing and always validates — and if even that fails it
//! is refused, never handed to `/ui`.
//!
//! **What it decides, and what it does not.** The confident output is the
//! theme: a small set of `--cf-*` tokens chosen from the brief's mood. Copy is
//! deliberately conservative — module and action headings humanized from the
//! names the surface already carries, never invented sentences. Applying the
//! result (setting the venture's [`UI_SPEC_KEY`] env, no redeploy) is the
//! provisioning engine's job (#7); this crate produces and validates the spec.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use factory0_core::SurfaceDocument;
use factory0_ui::{ActionSpec, ModuleSpec, Theme, UI_SPEC_VERSION, UiSpec, humanize};

pub use factory0_ui::UI_SPEC_KEY;

/// Why a brief could not be turned into a shippable spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// Even the theme-only fallback did not validate against the surface. The
    /// strings are the validator's own messages. This should not happen for a
    /// well-formed surface; it means the surface itself is the problem.
    Unvalidatable(Vec<String>),
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateError::Unvalidatable(errors) => {
                write!(f, "no valid spec for this surface: {}", errors.join("; "))
            }
        }
    }
}

impl std::error::Error for GenerateError {}

/// Produces a validated [`UiSpec`] for a venture from a one-line brief and its
/// surface.
///
/// The theme is chosen from the brief; module and action headings are
/// humanized from the surface's own names. The result is validated against the
/// surface; if it does not validate it is regenerated as theme-only, and only
/// refused if that also fails.
///
/// # Errors
///
/// [`GenerateError::Unvalidatable`] if no spec validates for the surface.
pub fn generate(brief: &str, surface: &SurfaceDocument) -> Result<UiSpec, GenerateError> {
    let tokens = theme_tokens(brief);
    let full = UiSpec {
        version: UI_SPEC_VERSION,
        theme: Theme {
            tokens: tokens.clone(),
            css_url: None,
        },
        modules: headings_for(surface),
    };
    if full.validate(surface).is_ok() {
        return Ok(full);
    }
    // Regenerate: a theme-only spec references nothing the surface must
    // declare, so it validates for any well-formed surface.
    let theme_only = UiSpec {
        version: UI_SPEC_VERSION,
        theme: Theme {
            tokens,
            css_url: None,
        },
        modules: BTreeMap::new(),
    };
    theme_only
        .validate(surface)
        .map(|()| theme_only)
        .map_err(GenerateError::Unvalidatable)
}

/// Validates a spec against a surface, returning it when it validates. The
/// generator uses this internally; it is exposed so a caller that assembles a
/// spec another way (a hand-written one, a future model output) can enforce
/// the same "never ship an unvalidatable spec" rule.
///
/// # Errors
///
/// The validator's messages when the spec references anything the surface does
/// not declare.
pub fn validated(spec: UiSpec, surface: &SurfaceDocument) -> Result<UiSpec, Vec<String>> {
    spec.validate(surface).map(|()| spec)
}

/// Serialises a spec to the JSON string a venture's `UI_SPEC` env holds.
#[must_use]
pub fn spec_json(spec: &UiSpec) -> String {
    // UiSpec is a plain data type; serialisation cannot fail.
    serde_json::to_string(spec).unwrap_or_else(|_| "{}".to_owned())
}

/// Module and action headings drawn only from the surface's own names, so the
/// result references nothing the surface does not declare.
fn headings_for(surface: &SurfaceDocument) -> BTreeMap<String, ModuleSpec> {
    let mut modules = BTreeMap::new();
    for module in &surface.modules {
        let mut actions = BTreeMap::new();
        for action in &module.surface.actions {
            actions.insert(
                action.name.clone(),
                ActionSpec {
                    title: Some(humanize(&action.name)),
                    ..ActionSpec::default()
                },
            );
        }
        modules.insert(
            module.name.clone(),
            ModuleSpec {
                title: Some(humanize(&module.name)),
                actions,
            },
        );
    }
    modules
}

// ---------------------------------------------------------------------------
// Theme from the brief
// ---------------------------------------------------------------------------

/// A named palette: a mood and the `--cf-*` tokens it sets. Tokens from a
/// later-matched mood override earlier ones, so a brief that names two moods
/// resolves deterministically to the last.
struct Mood {
    /// Words in a lowercased brief that select this mood.
    keywords: &'static [&'static str],
    /// The `--cf-*` tokens it contributes.
    tokens: &'static [(&'static str, &'static str)],
}

/// The mood vocabulary. Curated and small on purpose: each mood is a coherent
/// token bundle, and the base (applied first) guarantees every token has a
/// value even when the brief matches nothing.
const BASE: &[(&str, &str)] = &[
    ("--cf-accent", "#3b5bdb"),
    ("--cf-bg", "#ffffff"),
    ("--cf-fg", "#1a1a1a"),
    ("--cf-font", "system-ui, sans-serif"),
    ("--cf-radius", "8px"),
    ("--cf-maxw", "40rem"),
];

const MOODS: &[Mood] = &[
    Mood {
        keywords: &[
            "dark",
            "night",
            "record label",
            "music",
            "band",
            "club",
            "rock",
        ],
        tokens: &[
            ("--cf-bg", "#0b0b0f"),
            ("--cf-fg", "#f4f4f5"),
            ("--cf-accent", "#e8384f"),
            ("--cf-font", "\"Helvetica Neue\", Arial, sans-serif"),
            ("--cf-radius", "2px"),
        ],
    },
    Mood {
        keywords: &[
            "luxury", "elegant", "premium", "boutique", "couture", "fine",
        ],
        tokens: &[
            ("--cf-bg", "#12100e"),
            ("--cf-fg", "#f5efe6"),
            ("--cf-accent", "#c9a227"),
            ("--cf-font", "Georgia, \"Times New Roman\", serif"),
            ("--cf-radius", "0px"),
        ],
    },
    Mood {
        keywords: &[
            "wellness", "spa", "calm", "nature", "organic", "yoga", "green",
        ],
        tokens: &[
            ("--cf-bg", "#f4f7f2"),
            ("--cf-fg", "#243027"),
            ("--cf-accent", "#4b8a5a"),
            ("--cf-radius", "16px"),
        ],
    },
    Mood {
        keywords: &["playful", "fun", "kids", "bright", "bold", "party"],
        tokens: &[
            ("--cf-accent", "#ff5c00"),
            ("--cf-radius", "20px"),
            ("--cf-font", "\"Trebuchet MS\", system-ui, sans-serif"),
        ],
    },
    Mood {
        keywords: &["minimal", "clean", "simple", "monochrome", "plain"],
        tokens: &[
            ("--cf-accent", "#111111"),
            ("--cf-radius", "4px"),
            ("--cf-maxw", "34rem"),
        ],
    },
    Mood {
        keywords: &["tech", "startup", "saas", "developer", "app", "software"],
        tokens: &[
            ("--cf-accent", "#2f6fed"),
            ("--cf-font", "\"Inter\", system-ui, sans-serif"),
            ("--cf-radius", "10px"),
        ],
    },
    Mood {
        keywords: &["warm", "bakery", "cafe", "coffee", "food", "kitchen"],
        tokens: &[
            ("--cf-bg", "#fdf6ee"),
            ("--cf-fg", "#3a2c22"),
            ("--cf-accent", "#c25a2b"),
            ("--cf-radius", "12px"),
        ],
    },
];

/// The `--cf-*` tokens a brief resolves to: the base, then every matched
/// mood's tokens layered on in order.
fn theme_tokens(brief: &str) -> BTreeMap<String, String> {
    let hay = brief.to_lowercase();
    let mut tokens: BTreeMap<String, String> = BASE
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    for mood in MOODS {
        if mood.keywords.iter().any(|kw| hay.contains(kw)) {
            for (k, v) in mood.tokens {
                tokens.insert((*k).to_owned(), (*v).to_owned());
            }
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::{Action, ModuleSurface, Surface, SurfaceDocument, VentureSurface};

    fn document(modules: Vec<ModuleSurface>) -> SurfaceDocument {
        SurfaceDocument {
            surface_api: 1,
            harness_api: 1,
            venture: VentureSurface {
                name: "Demo".into(),
                public_url: "https://demo.example".into(),
            },
            modules,
            ui: None,
        }
    }

    fn module(name: &str, surface: Surface) -> ModuleSurface {
        ModuleSurface {
            name: name.into(),
            version: "1".into(),
            surface,
        }
    }

    /// A surface with one module and one fielded action (`email`).
    fn signup_document() -> SurfaceDocument {
        let schema = schemars::Schema::try_from(serde_json::json!({
            "type": "object",
            "properties": { "email": { "type": "string" } }
        }))
        .expect("schema");
        let surface = Surface::new().action(Action::post("join", "/join").input_schema(schema));
        document(vec![module("email-signup", surface)])
    }

    // -- theme ---------------------------------------------------------

    #[test]
    fn the_brief_picks_a_mood() {
        let dark = theme_tokens("a record label site, moody and dark");
        assert_eq!(dark.get("--cf-bg").map(String::as_str), Some("#0b0b0f"));
        let spa = theme_tokens("calm wellness spa");
        assert_eq!(spa.get("--cf-accent").map(String::as_str), Some("#4b8a5a"));
    }

    #[test]
    fn an_unmatched_brief_still_yields_a_full_base_theme() {
        let t = theme_tokens("something with no mood words at all");
        for key in [
            "--cf-accent",
            "--cf-bg",
            "--cf-fg",
            "--cf-font",
            "--cf-radius",
        ] {
            assert!(t.contains_key(key), "base always sets {key}");
        }
    }

    #[test]
    fn every_theme_token_is_a_cf_custom_property() {
        // The validator rejects any token key not starting with --cf-.
        let t = theme_tokens("luxury boutique record label");
        assert!(t.keys().all(|k| k.starts_with("--cf-")));
    }

    // -- generation ----------------------------------------------------

    #[test]
    fn a_brief_and_surface_produce_a_validated_spec_that_reflects_the_brief() {
        let doc = signup_document();
        let spec = generate("a bold playful launch page", &doc).expect("generates");
        // It validates against the surface (the harness's own check).
        assert!(spec.validate(&doc).is_ok());
        // It reflects the brief.
        assert_eq!(
            spec.theme.tokens.get("--cf-radius").map(String::as_str),
            Some("20px")
        );
        // It humanized the existing action, and invented no field.
        let action = spec.action("email-signup", "join").expect("action copy");
        assert_eq!(action.title.as_deref(), Some("Join"));
        assert!(action.fields.is_empty(), "no field copy is invented");
    }

    #[test]
    fn generation_names_only_modules_and_actions_the_surface_declares() {
        let doc = signup_document();
        let spec = generate("clean minimal", &doc).unwrap();
        assert_eq!(spec.modules.len(), 1);
        assert!(spec.modules.contains_key("email-signup"));
        let m = &spec.modules["email-signup"];
        assert_eq!(m.actions.keys().collect::<Vec<_>>(), vec!["join"]);
    }

    #[test]
    fn an_empty_surface_still_generates_a_theme_only_spec() {
        let doc = document(vec![]);
        let spec = generate("a warm little bakery", &doc).expect("generates");
        assert!(spec.modules.is_empty());
        assert!(spec.validate(&doc).is_ok());
        assert_eq!(
            spec.theme.tokens.get("--cf-accent").map(String::as_str),
            Some("#c25a2b")
        );
    }

    // -- refusal to invent ---------------------------------------------

    #[test]
    fn a_spec_naming_a_module_the_surface_lacks_is_refused() {
        let doc = signup_document();
        let mut bogus = UiSpec {
            version: UI_SPEC_VERSION,
            ..UiSpec::default()
        };
        bogus.modules.insert(
            "ghost-module".into(),
            ModuleSpec {
                title: Some("Ghost".into()),
                ..ModuleSpec::default()
            },
        );
        let err = validated(bogus, &doc).expect_err("must refuse an invented module");
        assert!(err.iter().any(|e| e.contains("ghost-module")), "{err:?}");
    }

    #[test]
    fn a_spec_naming_a_field_the_action_lacks_is_refused() {
        let doc = signup_document();
        let mut action = ActionSpec::default();
        action.fields.insert(
            "phone".into(), // the join action only has `email`
            factory0_ui::FieldSpec::default(),
        );
        let mut module = ModuleSpec::default();
        module.actions.insert("join".into(), action);
        let mut bogus = UiSpec {
            version: UI_SPEC_VERSION,
            ..UiSpec::default()
        };
        bogus.modules.insert("email-signup".into(), module);
        let err = validated(bogus, &doc).expect_err("must refuse an invented field");
        assert!(err.iter().any(|e| e.contains("phone")), "{err:?}");
    }

    #[test]
    fn generate_output_serialises_to_ui_spec_json() {
        let doc = signup_document();
        let spec = generate("tech startup", &doc).unwrap();
        let json = spec_json(&spec);
        // Round-trips through the harness parser, the same one /ui uses.
        let back = UiSpec::parse(&json).expect("valid ui spec json");
        assert_eq!(back, spec);
        assert_eq!(UI_SPEC_KEY, "UI_SPEC");
    }
}
