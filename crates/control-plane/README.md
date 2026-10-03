# cratefield-control-plane

The wasm entry point and composition root of the Cratefield control plane,
built on `Cratefield/harness` (see `../../docs/ARCHITECTURE.md`). Today it
answers `/__health`; the control-plane modules land with the epic's
children.

**Deployed** to https://console.cratefield.com by
`.github/workflows/deploy-control-plane.yml` on every `main` push that
touches it. The owner's one-time setup (Cloudflare token, GitHub secrets,
Worker secrets, the first operator), verification and rollback are in
[`docs/control-plane/DEPLOY.md`](../../docs/control-plane/DEPLOY.md).

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
