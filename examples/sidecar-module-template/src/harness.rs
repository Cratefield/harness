//! The harness this sidecar serves: one module, the Cloudflare runtime,
//! and the venture identity the host's answers depend on.

use crate::module::Notes;
use cratefield_core::{Harness, Venture};
use cratefield_runtime_cloudflare::Cloudflare;

/// The venture this module belongs to.
///
/// **These four values must match the host Worker's `src/harness.rs`
/// exactly: the name, the domain, `public_url` and the CORS origins.**
/// They are not decorative: confirmation and unsubscribe links are built
/// from `public_url`, and `cors_origins` decides which browser sites may
/// call this Worker at all. A sidecar whose `public_url` disagrees with
/// its host's is not an error anywhere — it is a silent wrong redirect
/// that shows up only when a customer clicks a link and lands on a
/// domain that does not exist.
///
/// There is deliberately one place to get them right, and it is this
/// block: a template cannot read the host's source across repositories,
/// so the values are set once, here, next to a comment that says what
/// breaks if they drift. Change them before the first deploy, not after.
const VENTURE_NAME: &str = "my-venture";
const VENTURE_DOMAIN: &str = "api.example.ventures";
const VENTURE_PUBLIC_URL: &str = "https://api.example.ventures";
const VENTURE_CORS_ORIGINS: [&str; 1] = ["https://example.ventures"];

/// Builds the harness the Worker serves. `build()` validates the module
/// against the runtime handed in — a port this module requires that the
/// runtime does not provide fails here, at startup, rather than as a 500
/// at request time.
///
/// # Panics
///
/// On an invalid harness, which for this composition can only be a
/// venture identity or a port the Cloudflare runtime has stopped
/// providing; both are deploy-time mistakes, not runtime conditions.
pub fn build(runtime: &Cloudflare) -> cratefield_core::Harness {
    Harness::builder()
        .venture(
            Venture::new(VENTURE_NAME, VENTURE_DOMAIN)
                .public_url(VENTURE_PUBLIC_URL)
                .cors_origins(VENTURE_CORS_ORIGINS),
        )
        .module(Notes::new())
        .runtime(runtime.clone())
        .build()
        .expect("sidecar template harness is valid")
}

/// The same harness with its own runtime, for the `fz` bin: it needs the
/// compiled-in modules to collect migrations and run the doctor, and it
/// serves nothing, so it builds an instance instead of borrowing one.
///
/// # Panics
///
/// Same conditions as [`build`].
pub fn harness() -> cratefield_core::Harness {
    build(&Cloudflare::new().db("DB"))
}
