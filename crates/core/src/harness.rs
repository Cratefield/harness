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
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::json;
use tracing::error;

use crate::admin::require_admin;
use crate::config::Config;
use crate::config::ConfigError;
use crate::events::EventBus;
use crate::http::{
    Json, MAX_BODY_BYTES, ScopeState, cors_layer, scope_layer, security_headers_layer,
    token_response_layer,
};
use crate::module::{HARNESS_API, Module, ModuleContext, harness_api_mismatch};
use crate::ports::Dispatcher;
use crate::ports::{Clock, Database, Port, Ports, Statement, SystemClock, warn_undeclared_ports};
use crate::problem::Problem;
use crate::sidecar::{
    GatewayGuard, SIDECAR_REQUIRE_GATEWAY, SidecarMount, X_HARNESS_GATEWAY, gateway_guard,
    gateway_signer, mint_gateway, truthy,
};
use crate::signer::HmacSigner;
use crate::surface::{
    MAX_SIDECAR_SURFACE_BYTES, RenderedSurface, SurfaceDocument, SurfaceSource, UiContext, UiMount,
    sanitize_sidecar_document, strip_unguarded_captcha_actions,
};
use crate::template::{Template, TemplateRegistry};
use crate::venture::{Venture, VentureEnv};

/// A runtime resolves environment bindings into [`Ports`] and declares
/// statically which ports it can provide, so `Harness::build` can reject a
/// module that requires something the runtime will never hand it
/// (ADR 0002). Reference implementation: `cratefield-runtime-cloudflare`.
pub trait Runtime: Send + Sync + 'static {
    fn provides(&self) -> Vec<Port>;
    /// Whether the named port is not merely present but usable for its
    /// production duty (issue #133): a captcha adapter that reports
    /// itself unbound cannot protect a `HumanForm` route, so the runtime
    /// that wraps it says "no" here even though `provides()` lists the
    /// port. Default: presence in `provides()`.
    fn effectively_configured(&self, port: Port) -> bool {
        self.provides().contains(&port)
    }
}

/// A built harness: immutable after `build()`.
pub struct Harness {
    venture: Arc<Venture>,
    modules: Vec<Arc<dyn Module>>,
    templates: Arc<TemplateRegistry>,
    events: EventBus,
    runtime: Option<Arc<dyn Runtime>>,
    /// The single module-provided `/.well-known` router, if any
    /// (issue #46); nested at the root by `router()`.
    well_known: Option<Router>,
    /// The composed UI surface (ADR 0010), rendered once for
    /// `GET /__surface`: the admin variant and the public subset.
    surface: Arc<SurfaceVariants>,
    /// The renderer mounted at `/ui`, if the venture chose one.
    ui: Option<Arc<dyn UiMount>>,
}

struct SurfaceVariants {
    document: Arc<SurfaceDocument>,
    full: RenderedSurface,
    public: RenderedSurface,
}

impl SurfaceVariants {
    fn compose(
        venture: &Venture,
        modules: &[Arc<dyn Module>],
        ui: Option<&Arc<dyn UiMount>>,
    ) -> Self {
        let mut document = SurfaceDocument::compose(venture, modules);
        document.ui = ui.and_then(|ui| ui.describe());
        Self {
            full: RenderedSurface::render(&document),
            public: RenderedSurface::render(&document.public()),
            document: Arc::new(document),
        }
    }
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
    /// per module; `cratefield-runtime-cloudflare` uses it for scheduled
    /// fan-out.
    pub fn module_context(&self, module: &dyn Module, ports: &Ports) -> ModuleContext {
        ModuleContext {
            config: Arc::clone(&ports.config),
            ports: ports.view_for(module),
            events: self.events.clone(),
            templates: Arc::clone(&self.templates),
            venture: Arc::clone(&self.venture),
            ui_mounted: self.ui.is_some(),
        }
    }

    /// The sidecar mounts that apply: read from configuration, not from
    /// the composition (ADR 0009), so the same artifact serves ventures
    /// with and without them. A malformed table mounts nothing and is
    /// logged; a mount that collides with an in-process module is
    /// dropped and logged. Neither takes down the in-process modules.
    /// This deployment's sidecar-role enforcement state (issue #131):
    /// whether the gate is closed, the key that verifies a stamp, and the
    /// sidecar's own admin token — which never crosses the boundary and is
    /// only ever re-asserted for a request the host already authorized.
    fn gateway_guard_state(ports: &Ports, gateway: Option<&Arc<HmacSigner>>) -> GatewayGuard {
        GatewayGuard {
            require: truthy(ports.config.as_ref(), SIDECAR_REQUIRE_GATEWAY),
            signer: gateway.map(Arc::clone),
            admin_token: ports
                .config
                .get("ADMIN_TOKEN")
                .filter(|token| !token.is_empty()),
        }
    }

    /// Nests one forwarding router per mounted sidecar (issue #131).
    /// Split out of [`Harness::router`] so that method stays readable.
    fn nest_sidecars(
        mut api: Router,
        mounted: &[SidecarMount],
        ports: &Ports,
        gateway: Option<&Arc<HmacSigner>>,
    ) -> Router {
        for mount in mounted {
            api = api.nest(
                &format!("/v1/{}", mount.name),
                crate::sidecar::router(
                    mount.clone(),
                    ports.dispatcher.clone(),
                    Arc::clone(&ports.config),
                    ports.rate_limiter.clone(),
                    gateway.map(Arc::clone),
                ),
            );
        }
        api
    }

    fn sidecar_mounts(&self, ports: &Ports) -> Vec<SidecarMount> {
        let mounts = match crate::sidecar::SidecarMounts::from_config(ports.config.as_ref()) {
            Ok(mounts) => mounts,
            Err(errors) => {
                for error in errors {
                    tracing::error!(error, "ignoring the sidecar mount table");
                }
                crate::sidecar::SidecarMounts::default()
            }
        };
        let module_names: Vec<&str> = self.modules.iter().map(|m| m.name()).collect();
        for collision in mounts.collisions(&module_names) {
            tracing::error!(error = collision, "ignoring the colliding sidecar mount");
        }
        mounts
            .iter()
            .filter(|m| !module_names.contains(&m.name.as_str()))
            .cloned()
            .collect()
    }

    /// The runtime this harness was validated against, if one was supplied.
    pub fn runtime(&self) -> Option<&Arc<dyn Runtime>> {
        self.runtime.as_ref()
    }

    /// The composed UI surface, admin actions included, for tooling
    /// (`fz`, the control plane). `GET /__surface` serves the same
    /// document, public subset unless the admin bearer is presented.
    #[must_use]
    pub fn surface(&self) -> &SurfaceDocument {
        &self.surface.document
    }

    /// Assembles the full router: each module nested under `/v1/<name>`,
    /// the one `/.well-known` router (if any) nested at the root,
    /// `GET /__health`, `GET /__ready`, `GET /__surface`, the UI renderer
    /// at `/ui` when one is mounted, and the shared middleware
    /// (request-id/Scope, CORS allowlist, 64 KiB body limit, `/v1/*`
    /// security headers, no-store headers for any request carrying a
    /// `token` query parameter — issue #135). Nothing but `/.well-known`,
    /// `/ui` and the `/__*` probes is ever mounted at the root.
    pub fn router(&self, ports: Ports) -> Router {
        let mut api = Router::new();
        for module in &self.modules {
            let ctx = self.module_context(module.as_ref(), &ports);
            api = api.nest(&format!("/v1/{}", module.name()), module.router(ctx));
        }
        // The gateway signer is this deployment's half of the sidecar
        // trust boundary (issue #131): absent secret, absent capability —
        // forwarded requests carry no stamp and a sidecar that requires one
        // will refuse them. The clock only expires tokens, so the default
        // system clock is fine when the runtime supplies none.
        let gateway = gateway_signer(
            ports.config.as_ref(),
            ports.clock.clone().unwrap_or_else(|| Arc::new(SystemClock)),
        );
        let mounted = self.sidecar_mounts(&ports);
        api = Self::nest_sidecars(api, &mounted, &ports, gateway.as_ref());
        let gateway_state = Self::gateway_guard_state(&ports, gateway.as_ref());
        let api = api
            .layer(axum::middleware::from_fn(security_headers_layer))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

        let surface_source: Arc<dyn SurfaceSource> = Arc::new(MergedSurface {
            base: Arc::clone(&self.surface),
            mounts: mounted,
            dispatcher: ports.dispatcher.clone(),
            gateway: gateway.clone(),
            env: self.venture.env,
            captcha_configured: ports.captcha.is_some(),
        });

        let ui = self.ui.as_ref().map(|ui| {
            ui.router(UiContext {
                surface: Arc::clone(&surface_source),
                api: api.clone(),
                config: Arc::clone(&ports.config),
                venture: Arc::clone(&self.venture),
                captcha_configured: ports.captcha.is_some(),
                signer: ports.signer.clone(),
                rate_limiter: ports.rate_limiter.clone(),
            })
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        });

        let Ports {
            config,
            db,
            mailer,
            captcha,
            rate_limiter: _,
            signer: _,
            kv: _,
            blob: _,
            push: _,
            payments: _,
            realtime: _,
            http: _,
            clock,
            id_gen,
            defer,
            dispatcher: _,
        } = ports;

        let health_state = HealthState {
            venture: Arc::clone(&self.venture),
            modules: self.modules.clone(),
            harness_build: config
                .get("HARNESS_BUILD")
                .filter(|build| !build.is_empty()),
            mailer_configured: mailer.is_some(),
            captcha_configured: captcha.is_some(),
        };

        let scope_state = ScopeState {
            defer: defer.unwrap_or_else(|| Arc::new(crate::ports::NoopDefer)),
            id_gen: id_gen.unwrap_or_else(|| Arc::new(crate::ports::UlidIdGen)),
        };
        let ready_state = ReadyState {
            db,
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
        };

        let surface_state = SurfaceState {
            config,
            source: surface_source,
        };

        let root = Router::new()
            .route("/__health", get(health_handler))
            .with_state(health_state)
            .route("/__ready", get(ready_handler))
            .with_state(ready_state)
            .route("/__surface", get(surface_handler))
            .with_state(surface_state)
            .merge(api);
        let root = match &self.well_known {
            Some(well_known) => root.nest(
                "/.well-known",
                well_known
                    .clone()
                    .layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
            ),
            None => root,
        };
        let root = match ui {
            Some(ui) => root.nest("/ui", ui),
            None => root,
        };

        // Innermost layer: the gate runs after `Scope`, so refusals carry
        // the request id, and it wraps every route — nested `/v1/*`, `/ui`
        // and `/__surface` alike (issue #131). Tower order: the layer
        // applied first is the innermost, so this line must come before
        // `scope_layer` in the chain.
        root.layer(from_fn_with_state(gateway_state, gateway_guard))
            .layer(from_fn_with_state(scope_state, scope_layer))
            .layer(axum::middleware::from_fn(token_response_layer))
            .layer(cors_layer(&self.venture.cors_origins))
    }
}

#[derive(Clone)]
struct HealthState {
    venture: Arc<Venture>,
    modules: Vec<Arc<dyn Module>>,
    /// Git sha injected as a var by the deploy workflow (issue #14).
    harness_build: Option<String>,
    mailer_configured: bool,
    captcha_configured: bool,
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
        "harness_api": HARNESS_API,
        "harness_build": state.harness_build,
        // Port presence: the Mailer/Captcha traits carry no probe, so a
        // NotConfigured adapter still reports its port as configured.
        "mailer": if state.mailer_configured { "configured" } else { "not_configured" },
        "captcha": if state.captcha_configured { "configured" } else { "absent" },
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
            crate::logging::forward_internal_error(&format!("readiness probe query failed: {err}"));
            Problem::not_ready("database query failed").into_response()
        }
        None => Problem::not_ready("database did not answer within 2 s").into_response(),
    }
}

#[derive(Clone)]
struct SurfaceState {
    config: Arc<dyn Config>,
    source: Arc<dyn SurfaceSource>,
}

/// The build-time surface plus whatever the mounted sidecars answer
/// (issue #76). Sidecar surfaces are fetched on every call: a sidecar's
/// own `/__surface` is prerendered, the service binding runs on the same
/// thread (ADR 0009), and a cache here would hide a redeploy. Only the
/// public part of a sidecar merges: its admin routes take its own token,
/// which this host does not hold.
struct MergedSurface {
    base: Arc<SurfaceVariants>,
    mounts: Vec<SidecarMount>,
    dispatcher: Option<Arc<dyn Dispatcher>>,
    /// Mints the gateway stamp for `/__surface` fetches: the host is not
    /// exempt from the boundary it enforces on others (issue #131).
    gateway: Option<Arc<HmacSigner>>,
    env: VentureEnv,
    captcha_configured: bool,
}

impl MergedSurface {
    /// What each mounted sidecar contributes, in mount order.
    async fn sidecar_modules(&self) -> Vec<crate::surface::ModuleSurface> {
        let mut extra = Vec::new();
        let Some(dispatcher) = &self.dispatcher else {
            return extra;
        };
        for mount in &self.mounts {
            if !dispatcher.has(&mount.binding) {
                continue;
            }
            let mut builder = axum::http::Request::builder()
                .method(axum::http::Method::GET)
                .uri("/__surface")
                .header(header::ACCEPT, "application/json");
            if let Some(signer) = &self.gateway {
                // A surface fetch is not an admin request: the plain purpose.
                builder =
                    builder.header(X_HARNESS_GATEWAY, mint_gateway(signer, &mount.name, false));
            }
            let request = builder
                .body(bytes::Bytes::new())
                .expect("static request builds");
            let answer = match dispatcher.dispatch(&mount.binding, request).await {
                Ok(response) if response.status().is_success() => response,
                Ok(response) => {
                    tracing::warn!(module = mount.name, status = %response.status(), "sidecar surface not available");
                    continue;
                }
                Err(err) => {
                    tracing::warn!(module = mount.name, error = %err, "sidecar surface fetch failed");
                    continue;
                }
            };
            // Cap before parsing: an unbounded document turns a merge into
            // a memory attack on this Worker (issue #131).
            if answer.body().len() > MAX_SIDECAR_SURFACE_BYTES {
                tracing::warn!(
                    module = mount.name,
                    "sidecar surface exceeds {MAX_SIDECAR_SURFACE_BYTES} bytes and was not merged"
                );
                continue;
            }
            match serde_json::from_slice::<SurfaceDocument>(answer.body()) {
                Ok(document) => match sanitize_sidecar_document(&document, &mount.name) {
                    Ok(entries) => extra.extend(entries.into_iter().filter_map(|mut entry| {
                        // A production host with no Captcha port cannot
                        // render the widget a merged action demands, so the
                        // honest surface drops it (issue #131).
                        if self.env == VentureEnv::Production
                            && !self.captcha_configured
                            && strip_unguarded_captcha_actions(&mut entry.surface) > 0
                        {
                            tracing::warn!(
                                module = entry.name,
                                "merged sidecar actions requiring a captcha were dropped: no Captcha port here"
                            );
                        }
                        (!entry.surface.is_empty()).then_some(entry)
                    })),
                    Err(problems) => {
                        for problem in problems {
                            tracing::warn!(module = mount.name, error = problem, "sidecar surface rejected at merge");
                        }
                    }
                },
                Err(err) => {
                    tracing::warn!(module = mount.name, error = %err, "sidecar surface is not a surface document");
                }
            }
        }
        extra
    }
}

#[async_trait::async_trait]
impl SurfaceSource for MergedSurface {
    async fn current(&self) -> Arc<SurfaceDocument> {
        if self.mounts.is_empty() {
            return Arc::clone(&self.base.document);
        }
        let mut document = (*self.base.document).clone();
        document.modules.extend(self.sidecar_modules().await);
        Arc::new(document)
    }

    fn built(&self) -> Arc<SurfaceDocument> {
        Arc::clone(&self.base.document)
    }

    fn rendered(&self, admin: bool) -> Option<&RenderedSurface> {
        Some(if admin {
            &self.base.full
        } else {
            &self.base.public
        })
    }
}

/// `GET /__surface` (ADR 0010): the composed surface, public subset by
/// default, admin actions included when `Authorization: Bearer
/// <ADMIN_TOKEN>` is valid. A wrong or stale bearer is not an error here,
/// it just gets the public document: this route exists to be read by
/// renderers and tooling, and a `403` would leak whether admin is on.
/// Strong `ETag` per variant; `If-None-Match` answers `304`.
///
/// Both variants share this URL, so caching is split per variant (issue
/// #130): the public document stays `no-cache` (shared caches may store
/// it but must revalidate — nothing in it is a secret), while the
/// authenticated document is `private, no-store` on the `200` *and* on
/// the `304`, because a `304` refreshes what a cache already holds.
/// `Vary: Authorization` alone is not enough: an intermediary that
/// ignores `Vary` could otherwise store the admin variant and expose it
/// to an unauthenticated caller.
async fn surface_handler(
    State(state): State<SurfaceState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let admin = require_admin(&*state.config, &headers).is_ok();
    // With no sidecar the source hands back the build-time Arc, and the
    // prerendered variants are reused; with sidecars the merged document
    // is rendered per request (a hash, microseconds).
    let current = state.source.current().await;
    let built = state.source.built();
    let prerendered = Arc::ptr_eq(&current, &built).then(|| state.source.rendered(admin));
    let fresh;
    let rendered: &RenderedSurface = if let Some(rendered) = prerendered.flatten() {
        rendered
    } else {
        fresh = if admin {
            RenderedSurface::render(&current)
        } else {
            RenderedSurface::render(&current.public())
        };
        &fresh
    };
    let matches = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|tag| tag == "*" || tag == rendered.etag)
        });
    let mut response = if matches {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(header::CONTENT_TYPE, "application/json")],
            rendered.json.clone(),
        )
            .into_response()
    };
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::ETAG,
        header::HeaderValue::from_str(&rendered.etag).expect("hex etag is a valid header"),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        if admin {
            header::HeaderValue::from_static("private, no-store")
        } else {
            header::HeaderValue::from_static("no-cache")
        },
    );
    response_headers.insert(
        header::VARY,
        header::HeaderValue::from_static("Authorization"),
    );
    response
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
    ui: Option<Arc<dyn UiMount>>,
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

    /// Adds an already-shared module (`cratefield-testing` keeps handles to
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

    /// Mounts a UI renderer at `/ui` (ADR 0010): `cratefield_ui::Ui`. Off
    /// unless called, so a venture without a UI serves nothing there.
    #[must_use]
    pub fn ui(mut self, ui: impl UiMount) -> Self {
        self.ui = Some(Arc::new(ui));
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
    /// or duplicated port declarations, duplicate module names, tables or
    /// `/.well-known` routers, `harness_api` mismatches, invalid UI
    /// surfaces, unprovided required ports, and template ids naming
    /// unregistered modules.
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
                errors.push(harness_api_mismatch(module.as_ref()));
            }

            let name = module.name();
            if name.is_empty() || !is_module_name(name) {
                errors.push(format!(
                    "module name `{name}` must be kebab-case ([a-z0-9]+ separated by '-')"
                ));
            }
            if names.insert(name, 1).is_some() {
                errors.push(format!("duplicate module name `{name}`"));
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

            module.surface().validate(name, &mut errors);

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

        let well_known = collect_well_known(&self.modules, &mut errors);

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

        append_production_readiness(&venture, &self.modules, self.runtime.as_ref(), &mut errors);

        check_template_ids(
            self.overrides.iter().chain(self.module_templates.iter()),
            &names,
            &mut errors,
        );

        let surface = Arc::new(SurfaceVariants::compose(
            &venture,
            &self.modules,
            self.ui.as_ref(),
        ));
        if let Some(ui) = &self.ui {
            ui.validate(&surface.document, &mut errors);
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
            well_known,
            surface,
            ui: self.ui,
        })
    }
}

/// A template id's module part must name a registered module.
fn check_template_ids<'a>(
    ids: impl Iterator<Item = &'a (String, Box<dyn Template>)>,
    names: &HashMap<&'static str, usize>,
    errors: &mut ConfigError,
) {
    for (id, _) in ids {
        let Some(module_name) = id.split('/').next() else {
            continue;
        };
        if !names.contains_key(module_name) {
            errors.push(format!(
                "template `{id}` names module `{module_name}` which is not registered"
            ));
        }
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

/// Collects the modules' `/.well-known` routers (issue #46): at most one
/// module may provide one — `/.well-known` is a singleton discovery
/// namespace — and more is a build error naming every provider.
/// Production abuse controls are an initialization rule, not a doctor
/// suggestion (issue #133): a venture that boots in production cannot
/// rely on captcha or payment verification it does not actually have.
/// `allow_no_captcha` is deliberately `None` here — the operator
/// override belongs to `fz doctor`'s deploy-time re-check, never to
/// the binary that ships.
fn append_production_readiness(
    venture: &Venture,
    modules: &[Arc<dyn Module>],
    runtime: Option<&Arc<dyn Runtime>>,
    errors: &mut ConfigError,
) {
    for error in crate::route_policy::production_readiness(
        venture.env,
        &crate::route_policy::WriteGuards::collect(modules),
        runtime,
        None,
    ) {
        errors.push(error);
    }
}

fn collect_well_known(modules: &[Arc<dyn Module>], errors: &mut ConfigError) -> Option<Router> {
    let mut providers: Vec<&'static str> = Vec::new();
    let mut well_known = None;
    for module in modules {
        if let Some(router) = module.well_known() {
            providers.push(module.name());
            well_known = Some(router);
        }
    }
    if providers.len() > 1 {
        let listed = providers
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(format!(
            "modules {listed} all provide a well-known router; at most one module may occupy /.well-known"
        ));
    }
    well_known
}
