//! The `Harness` builder and axum router assembly (issue #2, architecture
//! section 4).
//!
//! `Harness::build()` collects **all** configuration problems and reports
//! them together; `Harness::router(ports)` mounts every module under
//! `/v1/<name>` and adds `GET /__health` and `GET /__ready` plus the
//! middleware stack from architecture section 6.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::json;
use tracing::error;

use crate::config::ConfigError;
use crate::events::EventBus;
use crate::http::{
    Json, MAX_BODY_BYTES, ScopeState, cors_layer, scope_layer, security_headers_layer,
};
use crate::module::{HARNESS_API, Module, ModuleContext};
use crate::ports::{Clock, Database, Port, Ports, Statement, SystemClock, warn_undeclared_ports};
use crate::problem::Problem;
use crate::template::{Template, TemplateRegistry};
use crate::venture::Venture;

/// A runtime resolves environment bindings into [`Ports`] and declares
/// statically which ports it can provide, so `Harness::build` can reject a
/// module that requires something the runtime will never hand it
/// (ADR 0002). Reference implementation: `factory0-runtime-cloudflare`.
pub trait Runtime: Send + Sync + 'static {
    fn provides(&self) -> Vec<Port>;
}

/// A built harness: immutable after `build()`.
pub struct Harness {
    venture: Arc<Venture>,
    modules: Vec<Arc<dyn Module>>,
    templates: Arc<TemplateRegistry>,
    events: EventBus,
    runtime: Option<Arc<dyn Runtime>>,
}

impl std::fmt::Debug for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let modules: Vec<&str> = self.modules.iter().map(|m| m.name()).collect();
        f.debug_struct("Harness")
            .field("venture", &self.venture.name)
            .field("modules", &modules)
            .finish_non_exhaustive()
    }
}

impl Harness {
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::default()
    }

    pub fn venture(&self) -> &Arc<Venture> {
        &self.venture
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn templates(&self) -> &Arc<TemplateRegistry> {
        &self.templates
    }

    pub fn events(&self) -> &EventBus {
        &self.events
    }

    /// Builds the context a module sees: its declared ports (view), the
    /// config, the shared bus, templates and venture. `router()` uses this
    /// per module; `factory0-runtime-cloudflare` uses it for scheduled
    /// fan-out.
    pub fn module_context(&self, module: &dyn Module, ports: &Ports) -> ModuleContext {
        ModuleContext {
            config: Arc::clone(&ports.config),
            ports: ports.view_for(module),
            events: self.events.clone(),
            templates: Arc::clone(&self.templates),
            venture: Arc::clone(&self.venture),
        }
    }

    /// The runtime this harness was validated against, if one was supplied.
    pub fn runtime(&self) -> Option<&Arc<dyn Runtime>> {
        self.runtime.as_ref()
    }

    /// Assembles the full router: each module nested under `/v1/<name>`,
    /// `GET /__health`, `GET /__ready`, and the shared middleware
    /// (request-id/Scope, CORS allowlist, 64 KiB body limit, `/v1/*`
    /// security headers).
    pub fn router(&self, ports: Ports) -> Router {
        let mut api = Router::new();
        for module in &self.modules {
            let ctx = self.module_context(module.as_ref(), &ports);
            api = api.nest(&format!("/v1/{}", module.name()), module.router(ctx));
        }
        let api = api
            .layer(axum::middleware::from_fn(security_headers_layer))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

        let Ports {
            config: _,
            db,
            mailer: _,
            captcha: _,
            rate_limiter: _,
            signer: _,
            kv: _,
            http: _,
            clock,
            id_gen,
            defer,
        } = ports;

        let health_state = HealthState {
            venture: Arc::clone(&self.venture),
            modules: self.modules.clone(),
        };

        let scope_state = ScopeState {
            defer: defer.unwrap_or_else(|| Arc::new(crate::ports::NoopDefer)),
            id_gen: id_gen.unwrap_or_else(|| Arc::new(crate::ports::UlidIdGen)),
        };
        let ready_state = ReadyState {
            db,
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
        };

        Router::new()
            .route("/__health", get(health_handler))
            .with_state(health_state)
            .route("/__ready", get(ready_handler))
            .with_state(ready_state)
            .merge(api)
            .layer(from_fn_with_state(scope_state, scope_layer))
            .layer(cors_layer(&self.venture.cors_origins))
    }
}

#[derive(Clone)]
struct HealthState {
    venture: Arc<Venture>,
    modules: Vec<Arc<dyn Module>>,
}

async fn health_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let modules: Vec<serde_json::Value> = state
        .modules
        .iter()
        .map(|module| {
            json!({
                "name": module.name(),
                "version": module.version(),
                "emits": module.emits(),
            })
        })
        .collect();
    Json(json!({
        "venture": state.venture.name,
        "env": state.venture.env.as_str(),
        "modules": modules,
    }))
}

#[derive(Clone)]
struct ReadyState {
    db: Option<Arc<dyn Database>>,
    clock: Arc<dyn Clock>,
}

/// `GET /__ready`: `SELECT 1` through the `Database` port with a 2 s
/// timeout supplied by the runtime's clock; 503 problem on failure
/// (architecture section 6).
async fn ready_handler(State(state): State<ReadyState>) -> impl IntoResponse {
    let Some(db) = state.db else {
        return Problem::not_ready("database port is not configured").into_response();
    };
    let stmt = Statement::new("SELECT 1");
    let query = async move { db.query(&stmt).await };
    match crate::ports::timeout(&*state.clock, query, Duration::from_secs(2)).await {
        Some(Ok(_rows)) => Json(json!({ "ok": true })).into_response(),
        Some(Err(err)) => {
            error!(error = %err, "readiness probe query failed");
            Problem::not_ready("database query failed").into_response()
        }
        None => Problem::not_ready("database did not answer within 2 s").into_response(),
    }
}

/// Builder: `.venture(..)`, `.module(..)`, `.runtime(..)`, `.template(..)`,
/// then `.build()`.
#[derive(Default)]
pub struct HarnessBuilder {
    venture: Option<Venture>,
    modules: Vec<Arc<dyn Module>>,
    provides: Vec<Port>,
    runtime: Option<Arc<dyn Runtime>>,
    module_templates: Vec<(String, Box<dyn Template>)>,
    overrides: Vec<(String, Box<dyn Template>)>,
}

impl HarnessBuilder {
    #[must_use]
    pub fn venture(mut self, venture: Venture) -> Self {
        self.venture = Some(venture);
        self
    }

    /// Adds a module. Composition is compile-time: the wasm binary contains
    /// exactly the modules listed here (ADR 0003).
    #[must_use]
    pub fn module(mut self, module: impl Module) -> Self {
        self.modules.push(Arc::new(module));
        self
    }

    /// Adds an already-shared module (`factory0-testing` keeps handles to
    /// apply migrations and run conformance).
    #[must_use]
    pub fn module_arc(mut self, module: Arc<dyn Module>) -> Self {
        self.modules.push(module);
        self
    }

    /// Declares the runtime: its `provides()` set drives build-time
    /// checking of every module's `requires()`. The runtime is kept on the
    /// built harness for tooling (`fz doctor`, scheduled fan-out).
    #[must_use]
    pub fn runtime(mut self, runtime: impl Runtime) -> Self {
        let runtime: Arc<dyn Runtime> = Arc::new(runtime);
        self.provides = runtime.provides();
        self.runtime = Some(runtime);
        self
    }

    /// Registers module default templates (`<module>/<template>` ids).
    /// Call before overrides; see `template.rs` for the convention.
    #[must_use]
    pub fn templates(
        mut self,
        templates: impl IntoIterator<Item = (String, Box<dyn Template>)>,
    ) -> Self {
        self.module_templates.extend(templates);
        self
    }

    /// Venture template override. Wins over any module default with the
    /// same id; the id's module part must name a registered module.
    #[must_use]
    pub fn template(mut self, id: impl Into<String>, template: Box<dyn Template>) -> Self {
        self.overrides.push((id.into(), template));
        self
    }

    /// Validates everything, collecting **all** problems before failing
    /// (issue #2).
    ///
    /// # Errors
    ///
    /// `Err` whose `Display` lists every problem: invalid venture, unknown
    /// or duplicated port declarations, duplicate module names or tables,
    /// `harness_api` mismatches, unprovided required ports, and template
    /// ids naming unregistered modules.
    pub fn build(self) -> Result<Harness, ConfigError> {
        let mut errors = ConfigError::default();

        let venture = if let Some(venture) = self.venture {
            venture.validate(&mut errors);
            venture
        } else {
            errors.push("missing venture: call .venture(Venture::new(..)) before .build()");
            Venture::new("invalid", "invalid.invalid")
        };

        let mut names: HashMap<&'static str, usize> = HashMap::new();
        let mut tables: HashMap<&'static str, &'static str> = HashMap::new();

        for module in &self.modules {
            if module.harness_api() != HARNESS_API {
                errors.push(format!(
                    "module `{}` targets harness API {} but this core provides {}",
                    module.name(),
                    module.harness_api(),
                    HARNESS_API
                ));
            }

            let name = module.name();
            if name.is_empty() || !is_module_name(name) {
                errors.push(format!(
                    "module name `{name}` must be kebab-case ([a-z0-9]+ separated by '-')"
                ));
            }
            match names.get(name) {
                Some(_) => errors.push(format!("duplicate module name `{name}`")),
                None => {
                    names.insert(name, 1);
                }
            }

            for port in module.requires().iter().chain(module.optional()) {
                if !Port::ALL.contains(port) {
                    errors.push(format!(
                        "module `{name}` declares unknown port {}",
                        port.name()
                    ));
                }
            }
            for port in module.requires() {
                if module.optional().contains(port) {
                    errors.push(format!(
                        "module `{name}` lists port {} in both requires() and optional()",
                        port.name()
                    ));
                }
            }

            for table in module.tables() {
                match tables.get(table) {
                    Some(owner) => errors.push(format!(
                        "duplicate table `{table}` claimed by modules `{owner}` and `{name}`"
                    )),
                    None => {
                        tables.insert(table, name);
                    }
                }
            }
        }

        for module in &self.modules {
            for port in module.requires() {
                if !self.provides.contains(port) {
                    errors.push(format!(
                        "module `{}` requires port {} which the runtime does not provide",
                        module.name(),
                        port.name()
                    ));
                }
            }
            warn_undeclared_ports(module.as_ref(), &self.provides);
        }

        for (id, _) in self.overrides.iter().chain(self.module_templates.iter()) {
            let Some(module_name) = id.split('/').next() else {
                continue;
            };
            if !names.contains_key(module_name) {
                errors.push(format!(
                    "template `{id}` names module `{module_name}` which is not registered"
                ));
            }
        }

        errors.into_result()?;

        let mut registry = TemplateRegistry::new();
        registry.register_all(self.module_templates);
        registry.register_all(self.overrides);

        let mut events = EventBus::new();
        for module in &self.modules {
            for (name, handler) in module.events() {
                events = events.on(name, handler);
            }
        }

        Ok(Harness {
            venture: Arc::new(venture),
            modules: self.modules,
            templates: Arc::new(registry),
            events,
            runtime: self.runtime,
        })
    }
}

fn is_module_name(name: &str) -> bool {
    name.split('-').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}
