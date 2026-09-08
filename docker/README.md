# cratefield/forge — the compile engine in a container

The Docker packaging of the Factory Zero **compile engine** (Build Anywhere
packages 2 & 3). It carries the standalone `fz`, the Rust toolchain, the
`wasm32-unknown-unknown` target, and `worker-build`, so it can turn a venture
manifest into a compiled Worker with no local toolchain on the host.

## Build

From the harness repo root (the build context must be the repo, so the
image can compile the workspace):

```sh
docker build -f docker/Dockerfile -t cratefield/forge .
```

## Use

Generate a venture crate from a manifest:

```sh
docker run --rm -v "$PWD":/work cratefield/forge \
  build manifest.json --out dist
```

Then, inside the generated crate, `worker-build --release` compiles the
Worker (the image has it). `wrangler deploy` is deliberately **not** in the
image: deploying needs the account's Cloudflare credentials, a needs-human
step that a build container should not hold.

## Status

The Dockerfile is committed but **has not been built in CI yet** — it needs a
human `docker build` to validate on a machine with a Docker daemon. See the
PR description.
