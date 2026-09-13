// A test-support module, included with `mod support;` (or `mod common;`)
// into each test binary in this crate. `pub` is how a helper reads here,
// and the lint is right that nothing outside can reach it — the module is
// private to every binary that includes it. Saying so once beats
// `pub(crate)` on forty helpers.
#![allow(unreachable_pub)]
mod authenticator;
mod kit;

pub use authenticator::*;
pub use kit::*;
