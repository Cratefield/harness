//! `Config` over the process environment (`std::env`), the native
//! counterpart of the Workers `Env` adapter in
//! `factory0-runtime-cloudflare`. Modules still never touch `std::env`:
//! they receive the same [`Config`] trait object, filled here.

use factory0_core::Config;

/// Reads `SCREAMING_SNAKE` keys from the process environment. Secrets and
/// plain variables are the same thing natively — there is no separate
/// secret store, so the deployment (Docker, systemd) owns secret
/// injection (see the crate README's compose example).
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvConfig;

impl Config for EnvConfig {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|value| !value.is_empty())
    }
}
