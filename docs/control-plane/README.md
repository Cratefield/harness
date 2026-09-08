# Cratefield control plane

The managed service: sign in, pick modules, connect SSO, and get a running
harness venture on Cratefield's Cloudflare. It is itself a harness venture
(`docs/ARCHITECTURE.md`), consuming `Cratefield/harness` as pinned git
dependencies.

- **Epic and children:** issues in this repo, `EPIC #1`.
- **Pricing and the free tier:** #12.
- **Build the venture to wasm:** `cargo build --target wasm32-unknown-unknown -p cratefield-control-plane`.
