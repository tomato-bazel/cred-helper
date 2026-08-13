# fastverk/cred-helper

The fastverk **universal Bazel credential helper** and its reusable
`credresolve` core. Resolves the auth header for a Bazel fetch URI from a
host→connection registry, through pluggable secret backends — **keychain**
(local/mac), **env vars** (CI), and **file** — degrading to anonymous on any
miss so a fetch never fails the build.


## ⛔ Making a miss loud, for the hosts that must authenticate

This helper **fails open by design**: any miss yields `{"headers":{}}` and exit 0, so a fetch
degrades to anonymous rather than failing the build. That is correct for the common case —
most fetches in a Bazel build go to public hosts (BCR, crates.io, a public ghcr) that need no
credential, and a helper that errored on those would break every build immediately.

⛔ It has a cost, and this estate has paid it twice. A dead-code-eliminated config feature made
every private-ECR pull 401 and read as *"the C++ toolchain is broken"*; a helper timeout under
ECR minting read as *"RBE is starved"*. In both, the helper answered `{"headers":{}}` with exit
0, Bazel sent no `Authorization` header, and the far end returned `UNAUTHENTICATED` — so the
symptom named the wrong system entirely.

⭐ **`FASTVERK_CRED_REQUIRE` names the hosts that must authenticate**, comma-separated. For
those hosts only, a miss is a non-zero exit with a message naming the variable the helper
actually looks up:

```console
$ FASTVERK_CRED_REQUIRE=rbe.tbzl.dev cred-helper get <<<'{"uri":"https://rbe.tbzl.dev/"}'
cred-helper: no credential resolved for rbe.tbzl.dev, which FASTVERK_CRED_REQUIRE lists as requiring one.
...
Check that FASTVERK_TOKEN_FILE_RBE_TBZL_DEV names a readable, non-empty file
$ echo $?
1
```

⭐ **The asymmetry is what makes this safe.** Anonymous is a legitimate answer for a host nobody
said had to authenticate, and never a legitimate answer for one somebody did. So this is
**opt-in per host, never global** — a global strict mode is the version of this idea that gets
reverted the first afternoon.

⚠ Unset means today's behavior, exactly. Matching is exact and case-insensitive on the host,
with **no wildcards**, so `*` cannot sneak in as "require everything".


## Surfaces

| What | Where |
|---|---|
| **`credresolve`** (library) | the contract: `connection.proto` schema, the read/resolve path, and the `SecretStore` backends. `prost`-only, dependency-light. The single source of truth (fvkit layers `connect`/OAuth on top). |
| **`cred-helper`** (binary) | a thin wrapper implementing the Bazel credential-helper protocol over `credresolve::resolve`. |
| **`fastverk-oidc`** (binary) | the keyless CI path: trades a GitHub Actions OIDC token for a short-lived fastverk token (RFC 8693) and exports it as `FASTVERK_TOKEN_<HOST>`. Kept a separate crate so its TLS stack never enters the per-fetch helper. |
| **Prebuilt release artifacts** | see below — published per commit, credential-free. |

## Release artifacts

Every commit to `main` publishes both a rolling `credhelper-latest` and an
**immutable** `credhelper-<sha>`:

| Artifact | Platform |
|---|---|
| `cred-helper-darwin-arm64` | macOS, Apple silicon |
| `cred-helper-linux-amd64` | Linux x86-64 |
| `cred-helper-linux-arm64` | Linux aarch64 (Graviton runners, arm64 dev boxes) |
| `cred-helper-linux-amd64-layer.tar` | OCI layer installing `/usr/local/bin/cred-helper`, 0755 |
| `fastverk-oidc-linux-amd64` | Linux x86-64 |
| `fastverk-oidc-linux-arm64` | Linux aarch64 |
| `cred-helper-sha256.txt` | sha256 of every artifact above |

## Consume the prebuilt helper

Public releases — fetch with **no auth**.

⚠ Pin the **immutable** `credhelper-<sha>` tag, never the rolling
`credhelper-latest`: its bytes change under you every build. ⭐ Note the reason
is *only* that — `credhelper-latest`'s assets are always current. Its
`publishedAt` is frozen at the day the tag was created and `gh release list`
sorts by it, which has already caused it to be read as stale when it was not.
**A release's `publishedAt` is not its assets' freshness.**

```starlark
http_file(
    name = "fastverk_cred_helper_layer",
    urls = ["https://github.com/tomato-bazel/cred-helper/releases/download/credhelper-<sha>/cred-helper-linux-amd64-layer.tar"],
    sha256 = "<from cred-helper-sha256.txt>",
    downloaded_file_path = "cred-helper-linux-amd64-layer.tar",
)
```

⚠ `tomato-bazel`, not `fastverk` — the repo was transferred. GitHub redirects
the old org today, but a redirect is not a contract, and an `http_file` pinned
by `sha256` against one that stops redirecting is a fleet-wide fetch failure.

Add `@fastverk_cred_helper_layer//file` to your image `tars`, keep an unscoped
`--credential_helper=/usr/local/bin/cred-helper`.

## Runtime auth (credential-free artifacts)

Tokens are injected as **environment variables** per consuming CI job; the
helper resolves them at runtime. First non-empty wins:

- GitHub hosts → `GITHUB_TOKEN` / `GH_TOKEN` → `Authorization: Bearer`
- GitLab (gitlab.com) → `GITLAB_TOKEN` → `Authorization: Bearer`
- canonical form for any built-in connection: `FASTVERK_TOKEN_<ID>`
- **any other host** (e.g. a self-hosted GitLab) → `FASTVERK_TOKEN_<HOST>` (host
  uppercased, non-alphanumerics → `_`, e.g. `FASTVERK_TOKEN_GIT_EXAMPLE_COM`) →
  `Authorization: Bearer`. Nothing host-specific is baked into the tool.

On mac/local the helper reads the OS **Keychain** (via the fastverk app's
connection registry), which takes precedence over env.

## Build

⛔ **Bazel only.** A `cargo`-only path is treated as a defect here.

```sh
bazel test //... --keep_going                                      # host

# Cross-compile to either linux triple via the zig hermetic cc toolchain — this
# works from a mac, no linux builder needed. Same two platforms CI publishes.
bazel build //cred-helper:cred_helper_layer --platforms=//tools/oci:linux_amd64
bazel build //cred-helper:cred_helper       --platforms=//tools/oci:linux_arm64
bazel build //oidc:fastverk-oidc            --platforms=//tools/oci:linux_amd64
```
