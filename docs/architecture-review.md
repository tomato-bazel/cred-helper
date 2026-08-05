# cred-helper — architecture review

**Date:** 2026-08-05 · **Reviewed at:** `a920bfb` · **Size:** 1,599 lines of Rust
across 3 crates, plus one proto.

⚠ **This repository is public.** Nothing in this document is a secret, and
nothing in it may become one. The review was triggered by a live BuildBuddy API
key leaking into a public repo on 2026-08-04; reproducing a credential here
would be the same mistake with a shorter path.

---

## The single recommendation

⭐ **Make the helper fail loudly when a host it was configured to authenticate
resolves to no credential — and do it before anything else on this list.**

Everything else in this document is downstream of that. The redesign the estate
wants (stores as gRPC services behind a hub) *adds a new way for a credential to
silently not arrive*. Landing it on top of a helper that already fails open
would produce a system where "the hub is down" and "you typo'd an env var name"
and "everything is fine, this host is genuinely anonymous" are the same
observable event: an empty header, a 401 somewhere unrelated, and a build that
reads as broken for a reason that has nothing to do with credentials.

We have measured that failure mode at **97 of 97 targets failing with a valid
token sitting on disk**, and the surfaced error pointed nowhere near the helper.

⭐ **It is fixable.** See [§2](#2--fail-open-the-property-that-dominates). Bazel's
protocol does give the helper a loud channel — exactly one — and this repo
currently declines to use it.

---

## 1 · The system as built

### 1.1 Dispatch: request URI → header

Every arrow below is in the code today. The numbers are the order a request is
actually tried, which is **not** the order the module docs describe (see
[F-3](#f-3--config-arms-can-never-override-a-built-in-preset)).

```
  Bazel:  cred-helper get   <<< {"uri":"grpcs://rbe.tbzl.dev:8980/…"}
                │
                ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ cred-helper/src/main.rs :: respond()                                │
  └─────────────────────────────────────────────────────────────────────┘
                │
                ├─(a) uri::parse_request_uri(body)  ── hand-rolled JSON scanner,
                │        no serde on the hot path         uri.rs:35
                │        └─ miss ⇒ {"headers":{}}, exit 0
                ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ credresolve::connections::resolve(uri)          connections.rs:99   │
  └─────────────────────────────────────────────────────────────────────┘
                │
                ├─(b) uri::host_of(uri)  ── strips scheme, userinfo, PORT,
                │        keeps IPv6 brackets            uri.rs:8
                │        └─ "" ⇒ None
                │
                ├─(c) FASTVERK_TOKEN_FILE_<HOST>   ⭐ tried FIRST because it is
                │        the only REFRESHABLE source.  connections.rs:154
                │        env holds a PATH; file is re-read every invocation;
                │        response carries `expires` (now + 600s) so Bazel
                │        re-invokes instead of caching forever.
                │        └─ hit ⇒ Authorization: Bearer <file contents>
                │
                ├─(d) user registry  <config_dir>/connections.pb   (prost)
                │        match_host(): exact, or "*.suffix"        :62
                │
                ├─(e) …else default_registry(): the hardcoded presets
                │        ["github", "gitlab", "buildbuddy"]        :223
                │
                ├─(f) matched ⇒ secretstore::Resolver::standard()
                │        keychain → env → file, first non-empty wins
                │        └─ hit ⇒ <conn.header>: <conn.value_prefix><secret>
                │
                ├─(g) FASTVERK_TOKEN_<HOST>  generic per-host env  :209
                │        └─ hit ⇒ Authorization: Bearer <value>
                ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ credresolve::config::resolve_host(host)              config.rs:44   │
  │   $FASTVERK_CRED_CONFIG → JSON "arms"                               │
  │   hostPatterns[] + header + valuePrefix + secret{env|file|awsEcr}   │
  └─────────────────────────────────────────────────────────────────────┘
                │
                └─(h) no arm, or arm's secret unreadable
                            │
                            ▼
                   {"headers":{}}   exit 0     ⛔ INDISTINGUISHABLE FROM
                                                  "this host needs no auth"
```

### 1.2 Where it is host-keyed, and where that is brittle

| Site | Mechanism | Brittleness |
|---|---|---|
| `connections.rs:361` `canonical_env_var` | `host` → `FASTVERK_TOKEN_<UPPER>`, non-alphanumerics → `_` | ⛔ A **string-equality join between two processes with no schema between them.** The producer (a runner entrypoint) and the consumer (this helper) each compute the name independently. Nothing checks they agreed. This is the 97/97 failure. |
| `connections.rs:155` `host_file_token` | `canonical_env_var(host).replace("FASTVERK_TOKEN_", "FASTVERK_TOKEN_FILE_")` | ⛔ A **textual transform of a computed name**. Change the prefix in `canonical_env_var` and this silently produces a variable nothing sets — i.e. it fails open, and the test at `:523` would still pass because it hardcodes the expected name. |
| `oidc/src/main.rs:169` | A **second copy** of `canonical_env_var` | ⚠ There is a test asserting the two agree (`:191`), which is the right instinct — but it is a copy checked by a copy of the expectation, not one implementation. |
| `uri.rs:24` | **Port is stripped** | ⚠ `rbe.tbzl.dev:8980` and `rbe.tbzl.dev:443` are one host to this helper. For a REAPI endpoint on a non-standard port beside an HTTPS service on the same name, they cannot be given different credentials. |
| `connections.rs:245,256,267,287,349,379` | `match provider { "github" … "gitlab" … "buildbuddy" … }` | Six separate match/conditional sites keyed on one provider string. See [§4](#4--the-provider-model). |

⭐ **The contrast worth noticing:** `config.rs`'s arms are host-matched too, but
by `hostPatterns` — *data*, with wildcard semantics, in one file you can read.
A mismatch there is visible by opening the file. A mismatch in the env-var join
is visible nowhere. **The config-arm layer is already the better mechanism;
it is just tried last.**

---

## 2 · ⛔⛔ Fail-open: the property that dominates

### 2.1 What Bazel's protocol actually permits — measured, not assumed

Read from Bazel 9.2.0's implementation (`CredentialHelper.java`,
`GetCredentialsResponse.java`, `CredentialHelperCredentials.java`) and the
EngFlow spec this repo cites.

| Question | Answer | Consequence |
|---|---|---|
| Does a **non-zero exit** reach the user? | ✅ Yes. Bazel throws `CredentialHelperException`: `"Failed to get credentials for '<uri>' from helper '<path>': process exited with code <n>. stderr: <stderr>"` | ⭐ **This is the loud channel, and it names the URI, the helper, and our stderr.** It is everything a diagnostic needs. |
| Is **stderr** surfaced on a *successful* (exit 0) run? | ⛔ **No.** Bazel reads stderr into a reader and only interpolates it into exception messages. | ⛔ **"Warn loudly and keep going" is not available.** You cannot be both quiet-successful and loud. This kills the cheapest option and forces the design. |
| Does malformed JSON reach the user? | ✅ Yes — `"error parsing output. stderr: <stderr>"`. | Same channel. |
| Is there a timeout? | ✅ `--credential_helper_timeout`, default **10s**. Help text: *"Credential helpers failing to respond within this timeout will fail the invocation."* | See [§6.3](#63--the-hard-number-the-hub-design-must-respect). |
| Is `expires` real? | ✅ Yes. `GetCredentialsResponse` parses `expires` as RFC 3339 (`yyyy-MM-dd'T'HH:mm:ssXXX`), and unknown fields are ignored for forward compatibility. | The refresh mechanism at `connections.rs:115` genuinely works. |
| What if `expires` is **omitted**? | ⚠ `--credential_helper_cache_duration`, default **30m** — *not* "for the build". | ⭐ Worth knowing: every static (keychain/env) response this helper returns is cached **30 minutes**, then the helper is re-invoked. A rotated static secret is therefore picked up within 30 minutes without anyone designing for it. |
| How often is the helper invoked? | Once **per URI**, cached in a `Cache<URI, GetCredentialsResponse>`; `expires` (or the 30m default) bounds the entry. | ⭐ **Tens of invocations per build, not thousands.** Materially changes the latency argument in [§6](#6--the-redesign-stores-as-grpc-services-behind-a-hub). |
| What does the spec *recommend* on a miss? | > A helper that cannot provide credentials for a URI **SHOULD** return an error indicating the unsupported input instead of returning an output. | ⭐ **Today's blanket `{"headers":{}}` is a deliberate deviation from the spec's own advice.** |

### 2.2 ⛔ Why "just error on a miss" is wrong anyway

The spec's *SHOULD* assumes a **host-scoped** helper
(`--credential_helper=host=…`). This estate runs it **unscoped** — the in-cluster
CI image bakes `--credential_helper=/usr/local/bin/cred-helper` — so Bazel asks
this helper about *every* URI it fetches: `bcr.bazel.build`,
`static.crates.io`, zig SDK mirrors, `registry.tbzl.dev`. Erroring on every
miss would fail every anonymous fetch in the fleet.

⚠ The two invocation styles coexist today: `aion-mono`'s workflows scope it
(`--credential_helper=rbe.tbzl.dev=/tmp/cred-helper`), the CI image does not.
Any strictness design must be correct under **both**.

### 2.3 ⭐ The fix: claimed vs unclaimed

Split "I have no credential" into two distinct outcomes.

> **A host is CLAIMED when some piece of configuration named it.** An unclaimed
> host is anonymous and always was — stay silent. A claimed host that resolves
> to nothing is a **misconfiguration**, and must exit non-zero.

Claims already exist in the code; they just are not treated as claims:

1. a `Connection` in the user registry whose `host_patterns` match — `connections.rs:62`
2. a config arm whose `hostPatterns` match — `config.rs:63`
3. `FASTVERK_TOKEN_<HOST>` / `FASTVERK_TOKEN_FILE_<HOST>` set for exactly this host

and one that should be added:

4. `FASTVERK_CRED_REQUIRE=rbe.tbzl.dev,registry.tbzl.dev` — an explicit list, so
   a caller that *knows* it must authenticate a host can say so without relying
   on any of the above having been wired correctly.

Behavior: claim matched + secret resolved → header, exit 0. Claim matched +
secret missing/empty/unreadable → **stderr explaining which claim matched and
which source failed, exit 1**. No claim → `{"headers":{}}`, exit 0, as today.

⚠ Gate it behind `FASTVERK_CRED_STRICT=1` for one release so the fleet can adopt
it deliberately, then flip the default. (`setup-tbzl`'s design doc already asks
for exactly this flag by name, and records that the estate "has now paid for its
absence twice.")

### 2.4 ⛔ But claims alone would NOT have caught the 97/97 incident

Be honest about this. In that incident the env var name did not match the host,
so **the host was never claimed** — rules 1–3 stay silent. Claim-based
strictness catches "the secret is missing"; it does not catch "the secret is
present under a name nobody will ask for."

That failure needs the **inverse** check, and the inverse check cannot live
inside `get`: `get` sees one URI and has nothing to compare it against, and its
only loud channel is failure.

⭐ **It belongs in a `cred-helper doctor` subcommand**, run once before Bazel:

- enumerate every `FASTVERK_TOKEN*` variable set in the environment
- derive the host each one claims
- compare against the hosts the build is configured to talk to
  (`--remote_cache`, `--remote_executor`, `--credential_helper=host=…`, the
  registry list) — all of which `setup-tbzl` already knows, because it wrote them
- report any variable that claims a host nobody will ask about, **and** any
  configured host no variable claims

Rule 4 above (`FASTVERK_CRED_REQUIRE`) is the same idea compressed into the hot
path, for callers that cannot run a preflight.

⭐⭐ **And the structural fix that makes the whole class go away:
stop joining producer and consumer on a computed variable name.** A config arm
with explicit `hostPatterns` has no such join. Recommend `setup-tbzl` render a
`FASTVERK_CRED_CONFIG` arm instead of exporting `FASTVERK_TOKEN_FILE_<HOST>`;
keep the env convention as a documented fallback for callers that cannot write
a file.

---

## 3 · Findings

### F-1 · ⛔ The BuildBuddy key was in bazel's argv on every release run

`release.yml:54` (pre-fix):

```
REMOTE="--config=remote --remote_header=x-buildbuddy-api-key=${BUILDBUDDY_API_KEY}"
```

`--remote_header=…=$KEY` reads like "auth via a header," but it is an **argv
entry** — readable via `ps aux` / `/proc/<pid>/cmdline` by any other process on
the runner, for the whole build. ⛔ GitHub masks secrets in **log text**; it
cannot mask a command line, so the leak is invisible in the artifact that would
otherwise catch it.

**Fixed** in the companion PR, with a `sh_test` guard on the *shape*
(`--flag=…$SECRET`) rather than on the vendor — pointing a future cache at roma
the same way would be the same bug.

### F-2 · ⭐ The BuildBuddy remote cache never served a single hit

Bazel's `N processes:` line names every strategy that produced a result. Across
every release run, `remote cache hit` **never appears**.

| Run | Disk cache | Result |
|---|---|---|
| `30153785337` (07-25) | warm | **87s** — `780 disk cache hit, 784 internal, 1 darwin-sandbox` |
| `30126526020` (07-24) | ⛔ cold (`Cache not found for keys`) | **361s** — `784 internal, 781 darwin-sandbox` |

The cold run is precisely the case a remote cache exists to rescue. It executed
781 actions locally and the remote cache contributed nothing. What actually
makes this build fast is `bazel-contrib/setup-bazel`'s `disk-cache: true`
(87s vs 361s) — and that needs no credential.

⭐ **A remote cache that has never answered is not a trade-off. It is an unused
credential.** Removed in the companion PR; the repo secret can now be **deleted
rather than rotated**.

⛔ **It cannot be repointed at roma.** roma's REAPI cache is
`grpc://roma-cache.roma-cache.svc.cluster.local:8980` — ClusterIP, in-cluster
only, cleartext h2c. The public-looking `grpcs://romacache.fastverk.com:8980` in
fastverk's bazelrc has **no DNS record** (the LoadBalancer/external-dns/ACM
block is commented out). This repo's release job runs on GitHub-hosted
`macos-14`. There is no path from that runner to roma today, and `grpcs://`
against an h2c backend would fail the handshake even if there were.

### F-3 · Config arms can never override a built-in preset

`main.rs:71` tries `config::resolve_host` **after** `connections::resolve`
returns `None` — and `connections::resolve` internally ends with the generic
`FASTVERK_TOKEN_<HOST>` fallback (`:139`). So the precedence is:

```
file-token env  >  user registry  >  built-in presets  >  generic env  >  config arms
```

`config.rs:8` documents itself as sitting "between the user's keychain registry
and the built-in provider defaults." It does not. `main.rs:65-70` acknowledges
the discrepancy and explains that splitting `connections::resolve` was avoided.

⚠ Consequences: a config arm cannot change how `github.com` authenticates, and
a stray `FASTVERK_TOKEN_<HOST>` silently outranks an explicit, reviewed arm.
For the "match arms come from configuration" claim to be true, arms must sit
**above** the built-in presets and above the generic env fallback.

### F-4 · ⛔ `fastverk-oidc` is built and tested, but never published

`oidc/` is a workspace member, has a `rust_binary`, and its test passes. But:

- `release.yml`'s `paths:` filter does not list `oidc/**` — a change there
  triggers no release
- the build step never builds `//oidc:fastverk-oidc`
- confirmed against the live release: assets are `cred-helper-darwin-arm64`,
  `cred-helper-linux-amd64`, `cred-helper-linux-amd64-layer.tar`,
  `cred-helper-sha256.txt` — **no `fastverk-oidc`**

So the keyless-CI story this repo advertises has **no artifact a consumer can
fetch**. It builds green, which is why nobody noticed. (Compare the dead-code
bug `main.rs:53-63` already records: config that nothing reads is
indistinguishable from config that is wrong.)

### F-5 · ⛔ No `linux-arm64` artifact

Same asset list. `setup-tbzl`'s `action.yml:174-177` hard-fails when it needs
one. Graviton runners and arm64 dev machines cannot use the prebuilt helper.
This is a one-line addition to the release matrix (the zig toolchain for
`aarch64-unknown-linux-gnu` is **already registered** in `MODULE.bazel:35`).

### F-6 · ⭐ "`credhelper-latest` is stale" is FALSE — and worth recording as a way things lie

`setup-tbzl`'s design doc pins the immutable tag partly because
`credhelper-latest` supposedly "installs the *oldest* binary, predating
`FASTVERK_TOKEN_FILE_<HOST>`."

Checked by downloading both manifests:

```
credhelper-latest        f1efdc6c…  c699d363…  f70f156e…
credhelper-a920bfbf49ea  f1efdc6c…  c699d363…  f70f156e…   → byte-identical
```

⚠ **What misled it:** `gh release view credhelper-latest` reports
`publishedAt: 2026-06-16` and `gh release list` sorts by it, because
`gh release create` set it once and `gh release upload --clobber` does not touch
it. The **assets** are current (`updatedAt: 2026-07-25T10:05:12Z`).
⭐ **A release's `publishedAt` is not its assets' freshness.**

Pinning the immutable tag is still right — the rolling tag's bytes change under
you — but the stated reason is wrong, and a wrong reason gets fixed by the wrong
change. Recommend `release.yml` also `--notes`-refresh the rolling release so
its metadata stops lying.

### F-7 · ⚠ Keychain is silently absent off macOS

`credstore.rs:45` — on non-macOS, `get` returns `Ok(None)`. A Linux developer's
`KeychainStore` resolves nothing, forever, with no signal. It is correct
behavior for a fallback chain and it is another quiet hole; `doctor` should
report which backends are actually live on this platform.

### F-8 · ⚠ Stale org identity throughout

`README.md:25`, `Cargo.toml:13`, and `release.yml`'s header all say
`fastverk/cred-helper`. The repo is `tomato-bazel/cred-helper`. The README's
`http_file` example URL therefore points at the pre-transfer org. GitHub
redirects today; a redirect is not a contract, and `http_file` with a pinned
`sha256` against a redirect that stops redirecting is a fleet-wide fetch
failure. Low effort, non-zero risk.

---

## 4 · The provider model

### 4.1 What breaks if roma is added tomorrow

Eight edits, all in Rust, plus a release:

| # | Site | Change |
|---|---|---|
| 1 | `connections.rs:223` | `for provider in ["github", "gitlab", "buildbuddy"]` |
| 2 | `connections.rs:245` `default_host` | new match arm |
| 3 | `connections.rs:256` `default_client_id` | new condition (or not) |
| 4 | `connections.rs:287` `preset` | new match arm — header, `auth_kind`, `host_patterns` |
| 5 | `connections.rs:344` | the `bail!` message enumerating valid providers |
| 6 | `connections.rs:349` | `if provider == "buildbuddy" { "api-key" } else { "oauth" }` — a second provider conditional |
| 7 | `connections.rs:379` `env_aliases` | new match arm |
| 8 | `connection.proto:105` | the comment enumerating providers |

…then merge to `main`, wait for the tag-gated release, and **re-pin
`url` + `sha256` in every consumer**: `aion-mono`'s three workflow blocks (all
currently on `credhelper-a920bfbf49ea`), `setup-tbzl`'s `action.yml:78`, the CI
image, and five ConfigSet org manifests.

### 4.2 ⭐ But that is not actually the blocker, and the review should say so

**A config arm authenticates roma today, with zero Rust changes:**

```json
{"arms":[{"hostPatterns":["rbe.tbzl.dev","roma-cache.roma-cache.svc.cluster.local"],
          "header":"Authorization","valuePrefix":"Bearer ",
          "secret":{"file":{"path":"/session/rbe-token"}}}]}
```

⭐ **The presets are not "what the helper can authenticate." They are "what the
desktop app can OAuth-connect for you."** Those are two different registries
that happen to share a `Connection` message. Conflating them is the actual
design error, and it is why "add a provider" feels like it needs a Rust release
when the resolve path does not need one at all.

**Recommendation, in order:**

1. Fix precedence ([F-3](#f-3--config-arms-can-never-override-a-built-in-preset))
   so arms outrank presets. *Then the presets are genuinely just defaults.*
2. Move `preset()` and `env_aliases()` out of the resolve path — they exist for
   `fvkit`/`tbzl`'s `connect` flow. `default_registry()` stays as the
   zero-config fallback.
3. Only then consider a registry-driven preset table. ⚠ Cost if done as data:
   the OAuth endpoints, scopes, and header shapes become config, which means a
   malformed config can now change *where a token is sent*. `secretstore.rs:6-9`
   already states the right principle — config **selects** a compiled-in
   behavior and supplies parameters; it never injects behavior. Preserve that.

⛔ **Do not remove BuildBuddy from the source.** It is a supported connection
type with a live consumer (`tbzl/crates/tbzl/src/connect.rs`). Removing it from
*this repo's own build config* — which the companion PR does — is a different
and unrelated change.

---

## 5 · The rest of the questions

### 5.1 Two store abstractions — is one vestigial?

**Neither. They are a layer, not a rivalry**, and the naming hides that.

- `credstore.rs` — the **macOS keychain platform shim**: `cfg(target_os = "macos")`
  over the `keyring` crate, with a stub for everything else.
- `secretstore.rs` — the **backend abstraction**: a `SecretStore` trait with
  `KeychainStore` / `EnvStore` / `FileStore`. `KeychainStore::get` delegates
  straight to `credstore::get` (`secretstore.rs:60`).

⚠ The real problem is that `lib.rs:19` exports `credstore` publicly. That is a
**public bypass of the trait**: a caller can `credresolve::credstore::get(…)?`
and skip the `Resolver`'s degrade-on-error semantics, its ordering, and its
empty-string filtering.

**Recommend:** keep both, make `credstore` `pub(crate)`, and rename it to
`secretstore::keychain` (or `platform::keychain`) so the module name stops
implying a peer abstraction. This is a mechanical rename with no consumer
impact — nothing outside this repo depends on `credresolve` as a library yet.

### 5.2 Stores it supports vs should

| Store | Today | Cost to add | Verdict |
|---|---|---|---|
| macOS keychain | ✅ `credstore.rs` | — | Keep. It is the local bootstrap floor. |
| env | ✅ `EnvStore` | — | Keep, demote. It is the source of the fragile join. |
| file | ✅ `FileStore` (+ `KEY=VALUE` field extraction) | — | ⭐ **Keep and promote.** |
| **External Secrets Operator** | ✅ **already covered** | **zero** | ESO syncs into a k8s `Secret`; the Secret mounts as a file; `FileStore` reads it. ⭐ The gap was never the backend — it is that nothing tells the file backend *where to look* except a host-keyed env var. Fix that and ESO is done. |
| **k8s projected SA token (IRSA)** | ✅ covered by `file` | zero | `AWS_WEB_IDENTITY_TOKEN_FILE` is a file. |
| **AWS Secrets Manager** | ❌ | ⛔ **high, and the estate has already paid for the lesson** | See below. |
| Vault | ❌ | same shape as Secrets Manager | Same verdict. |
| Linux Secret Service / Windows CredMan | ❌ (stubs to `None`) | moderate | Worth doing for the Linux dev story; see [F-7](#f-7--keychain-is-silently-absent-off-macos). |

⛔ **The AWS-SDK-in-the-hot-path question is already settled by this repo's own
scar tissue.** `config.rs:167-172` records it: shelling `aws ecr
get-authorization-token` cost a PyInstaller cold start + STS
`AssumeRoleWithWebIdentity` + `GetAuthorizationToken`, **overran Bazel's
credential-helper window**, Bazel killed the helper, the fetch went anonymous,
ECR answered 401, and every private-ECR base pull died fleet-wide — reading as
"the C++ toolchain is broken." Worse, the timeout hit *before the cache could
be written*, so every call re-paid and re-died.

⭐ **Therefore: no network-backed store may ever be reached synchronously from
`get`.** Not by CLI, not by SDK, not through a hub. This is the binding
constraint on §6, and it is measured, not theoretical.

### 5.3 Is `oidc/` a separate crate for a good reason?

✅ **Yes, and the header (`oidc/src/main.rs:9-12`) states it correctly:** `ureq`
drags rustls + webpki into whatever links it. `credresolve` is prost +
`directories` + `serde_json`; the helper is exec'd per URI, so binary size is
startup cost. Keeping TLS out of the hot-path binary is right.

⚠ Two things weaken it:

- ⛔ **It is never released** ([F-4](#f-4--fastverk-oidc-is-built-and-tested-but-never-published)) — the boundary is well-drawn around something nobody can obtain.
- ⚠ `canonical_env_var` is duplicated (`oidc:169` vs `connections.rs:361`).
  Fix by having `oidc` depend on `credresolve` and call the real function. The
  cost is prost in a one-shot CI tool that already links rustls — negligible,
  and it deletes a copy that must be kept true by hand.

### 5.4 What `setup-tbzl` needs that cred-helper does not offer

`setup-tbzl` exists (`tomato-bazel/setup-tbzl`, branch
`marsh/autoconfigure-action`, tests green); the service it fetches from
(`config.tbzl.dev`) does not. It derives everything from one endpoint:

```
grpcs://rbe.tbzl.dev:8980
   ├──> --remote_executor / --remote_cache
   ├──> --credential_helper=rbe.tbzl.dev=<helper>
   └──> FASTVERK_TOKEN_FILE_RBE_TBZL_DEV        ⭐ derived, never typed
```

| It needs | Status | Where it lands in this review |
|---|---|---|
| `linux-arm64` binary | ❌ absent, hard-fails | [F-5](#f-5--no-linux-arm64-artifact) |
| `FASTVERK_CRED_STRICT=1` | ❌ absent, **asked for by name** | [§2.3](#23--the-fix-claimed-vs-unclaimed) — ⭐ this is the same recommendation, arrived at independently |
| A reliable rolling tag | ⚠ works; metadata lies | [F-6](#f-6--credhelper-latest-is-stale-is-false--and-worth-recording-as-a-way-things-lie) |
| A probe that answers "is this host authenticated?" | ❌ — it re-implements Bazel's request shape by hand (`src/credprobe.rs:54`) | ⭐ `cred-helper doctor` ([§2.4](#24--but-claims-alone-would-not-have-caught-the-9797-incident)) is exactly this, and it belongs in the helper where the resolution logic lives, not in a copy. |

⭐ **Nothing `setup-tbzl` needs changes the recommendations. It converges on
them.** It is also the right place to land the structural fix from §2.4:
`setup-tbzl` writes a `FASTVERK_CRED_CONFIG` arm with an explicit `hostPatterns`
instead of exporting a name-joined env var, and the fragile join disappears at
the only place that creates it.

### 5.5 ⛔ The `ps aux` claim — CONFIRMED, and worse than reported

**Not in this repo's OIDC path.** `fastverk-oidc` passes `--endpoint`,
`--target-host`, `--audience`, `--env-name` — all non-secret. The subject token
arrives via `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (env) and the exchange is a POST
body. ✅ There is no client secret in it at all: RFC 8693 with no client
authentication.

**But the callers that feed it do leak, in two shapes:**

⚠ *(Both are outside this repository. Reported here because the fix belongs to
this repository's surface; no change to them is proposed in either PR.)*

1. **In-cluster build-runner pods** — `fastverk/deploy/build-runner/entrypoint.sh:386`,
   and five sibling copies:

   ```
   curl -fsS -u "${RBE_CLIENT_ID}:${RBE_CLIENT_SECRET}" -d grant_type=client_credentials …
   ```

   HTTP Basic via `-u`, so not literally `-d client_secret=` — but still argv.
   Exposure is the transient `curl` every `RBE_TOKEN_REFRESH_SECS` (2400s).

2. ⛔⛔ **GitHub Actions runners** — `aion-mono/.github/workflows/build.yml`, three
   copies (`239-268`, `663-694`, `1097-1128`) plus `release-toolchain.yml:184`.
   The refresh loop is `nohup bash -c '…'"$RBE_CLIENT_SECRET"'…' &`, which
   **interpolates the plaintext secret into the script text that becomes
   `bash -c`'s single argv element**. That process sleeps in a loop for the
   **entire build**, so the secret is continuously readable in `ps aux` and
   `/proc/<pid>/cmdline`. This is the strongest form of the claim, and it is
   real.

⭐ **The clean pattern already exists in the estate:**
`tbzl-build-operator/cmd/rbe-probe/main.go:342` reads
`os.Getenv("RBE_CLIENT_SECRET")` into `clientcredentials.Config` — in-process,
never argv. And secret *delivery* into pods is clean everywhere
(`secretKeyRef`); the leak is created by the shell that mints, not by k8s.

**The fix, and why it belongs here:** the minting loop is a credential-refresh
loop that every consumer hand-rolls in shell. That is precisely what a
credential helper is for. ⭐ **Move minting into `cred-helper` as a
client-credentials secret source** — an arm shape alongside `awsEcr`, reading
`client_secret` from a file or env, never from argv, with the same
write-file-and-advertise-`expires` refresh contract that already works
(`connections.rs:104-117`). That deletes four shell copies, closes the argv
exposure, and removes a whole class of hand-transcription — the same argument
`setup-tbzl` makes for endpoints.

⚠ Note the cost honestly: that is an HTTPS client on (or beside) the hot path,
which §5.2's constraint forbids doing synchronously. It must be the
background-refresher shape, not the resolve-time shape. See §6.4.

---

## 6 · The redesign: stores as gRPC services behind a hub

**Verdict: the interface is right, the transport split is right, the hub is
right for remote stores only — and it must not be built first.**

### 6.1 ✅ What is right about it

Making the store contract a proto `service` is a genuine improvement, for a
reason sharper than "protos are good":

⭐ **A trait is a compile-time contract; a service is a deployment-time
contract.** Adding AWS Secrets Manager as a `SecretStore` impl is a Rust change
plus a tag-gated release plus N consumer re-pins ([§4.1](#41--what-breaks-if-roma-is-added-tomorrow)).
Adding it as a service implementation is a deploy. That is exactly the coupling
that has cost this estate repeatedly.

⭐ The hub also fixes something the current design has no answer for: **a shared
cache**. Today each helper invocation is a fresh process with no memory, which
is why the ECR arm had to invent a temp-file token cache (`config.rs:181`) and
why the refresh story is a file on disk written by an unrelated shell loop. A
warm hub is the natural home for both.

### 6.2 ⛔ What is wrong about it, stated plainly

**1. It does not decouple what the brief says it decouples.** Adding *roma as a
provider* is not blocked by the store abstraction — it is blocked by the preset
match arms and by precedence ([§4.2](#42--but-that-is-not-actually-the-blocker-and-the-review-should-say-so)),
neither of which a store service touches. A config arm authenticates roma today.
⚠ Shipping a hub and then discovering you still need a Rust release to add a
provider would be a demoralizing and avoidable outcome.

**2. tonic's generated trait is `async`.** `cred-helper` is fully sync and links
prost only. Implementing a tonic-generated `SecretStore` in-process means a
tokio runtime in the hot-path binary. `tomato-bazel/gate`'s `//proto:prost_toolchain`
exists **specifically** to avoid this ("would make the report binary depend on
an async runtime it never starts"). ⭐ Resolution in [§7.2](#72--two-toolchains-from-one-proto).

**3. ⛔⛔ It must not land before fail-open is fixed.** A hub adds a new way for
a credential to silently not arrive. On today's helper, "hub down" produces the
same observable as "host is genuinely anonymous": an empty header and a 401
somewhere unrelated. **You would be unable to distinguish them during an
incident.** This is not a sequencing preference; it is the difference between a
debuggable system and the 97/97 outage repeated with more moving parts.

### 6.3 ⭐ The hard number the hub design must respect

`--credential_helper_timeout` defaults to **10s**, and a helper that misses it
**fails the invocation**. ⚠ The in-cluster entrypoint has **already raised it to
60s** (`entrypoint.sh:584`) — a 6× increase, granted *before* a hub exists.
That is evidence the hot path is under pressure today, and that the headroom a
hub would want has already been spent.

Combined with the ECR incident ([§5.2](#52--stores-it-supports-vs-should)):

> ⭐⭐ **Every `get` must answer from cache, within milliseconds, always. The hub
> may refresh in the background; it may never block a `get` on a remote call.**

⭐ That reframes the hub from "a router that calls backends" to **"a cache with a
background refresher."** Which is a much safer object — and note it is what
`FASTVERK_TOKEN_FILE_<HOST>` plus the runner's refresh loop already *are*,
minus the schema, minus the type safety, and minus a place to put the logic
that four repos currently duplicate in shell.

### 6.4 The shape, if it is built

**Latency, corrected.** The brief's premise — "a network hop in front of every
Bazel action" — overstates it. Bazel caches helper responses in a
`Cache<URI, GetCredentialsResponse>`, so the helper runs **once per URI**, TTL-bounded
by `expires`: tens to low hundreds of invocations per build, not thousands. And
each is already a `fork`/`exec` (~1–3 ms); a warm Unix-domain-socket round trip
adds ~0.3–1 ms. ⭐ **Latency is not the reason to be careful. The ECR timeout
incident is.**

**Placement — recommend per-pod sidecar (and no hub at all locally):**

| Topology | Blast radius | Caller authz | Verdict |
|---|---|---|---|
| per-cluster | ⛔ every build in the estate | required (mTLS/SPIFFE) — reintroduces bootstrap | No. It also becomes a network service that holds every tenant's credentials. |
| per-node (DaemonSet) | one node | ⛔ required — pods of different tenants share it | No, unless tenant isolation is solved first. |
| **per-pod sidecar** | **one build** | **none — the pod boundary is the boundary** | ⭐ **Yes.** Credentials never leave the pod. ⚠ Must set resource `requests`, or Karpenter reads the node as 0%-utilized and evicts it. |
| **local dev: none** | — | — | ⭐⭐ **Non-negotiable.** In-process stores stay the default. If a developer must start a daemon before `bazel build` works, this tool got worse, and the local story matters as much as the CI story. |

**Bootstrap.** ⭐ The hub's own credential must come from a store that needs no
credential: a **file** (the projected SA token for IRSA) or the **OS keychain**.
Those two therefore can never move behind the hub — they are the floor. This is
not a convenience; it is why the in-process/remote split is structural rather
than an optimization.

**Failure modes, answered explicitly:**

| Event | Required behavior |
|---|---|
| Hub socket absent | ⭐ Fall through to in-process stores, silently. Absent hub = not configured. |
| Hub configured (`FASTVERK_CRED_HUB` set) but unreachable | ⛔ **exit non-zero with a message naming the socket.** This is a claim under [§2.3](#23--the-fix-claimed-vs-unclaimed) rule 4. Never anonymous. |
| Hub reachable but slow | ⛔ Client deadline well under `--credential_helper_timeout` (recommend 1s). On deadline: exit non-zero. ⚠ Never "wait and hope" — that is the ECR failure exactly. |
| Hub returns NOT_FOUND for a claimed host | ⛔ exit non-zero. |
| Hub returns NOT_FOUND for an unclaimed host | ✅ `{"headers":{}}`, exit 0. |

**Caching and rotation.** The hub caches per `SecretRef`, TTL from the store's
`expires_at`. ⚠ **A rotated credential is picked up at TTL, not immediately** —
that is already the model (`file_token_ttl_secs`, 600s default), and it should
be *data* in the response rather than a compiled-in constant. Push-based
invalidation (watching the k8s Secret / ESO refresh) is a real feature with real
cost — ⛔ **explicitly out of scope for v1**; do not let it into the first
design or it will not ship.

**Bootstrap cost, honestly.** A hub that must be deployed before a build can
authenticate is a new dependency for every consumer, on a path that currently
requires only a 5.5 MB static binary in a layer tar. ⚠ For CI that is a sidecar
in a pod spec — real but bounded. ⭐ For local development it must be **zero**,
which is why in-process stays the default and the hub is opt-in via an
environment variable that is *absent* by default.

---

## 7 · Toolchain: proto-first, and killing `build.rs`

### 7.1 ⛔ The current codegen path is the defect

`credresolve/build.rs` compiles the proto with `prost-build`, reached from
`CARGO_MANIFEST_DIR` as `../proto/...`, wrapped in `cargo_build_script` with
`PROTOC` injected. Wrapping it makes Bazel *run* a cargo build script; it does
not make it a Bazel proto build. The proto is not a `proto_library`, so nothing
else in the estate can depend on it, and there are two codegen paths to keep
true.

✅ **`build.rs` can and should be deleted.** Replace with `proto_library` +
`rust_prost_library`.

⚠ Two consequences to state, not gloss:

1. **`cargo build -p credresolve` stops working.** That is intended — this
   estate treats a cargo-only path as a defect — but `Cargo.toml`/`Cargo.lock`
   remain load-bearing for `crate_universe`'s `from_cargo`. Only *proto codegen*
   leaves cargo.
2. ⭐ **`lib.rs`'s `include!` becomes a re-export.** Today
   `pub mod proto { include!(concat!(env!("OUT_DIR"), "/fastverk.v1.rs")); }`.
   With `rust_prost_library` the generated code is a **separate crate named
   after the `proto` target, not the `rust_prost_library` target** — so
   `rust_prost_library(name = "connection_rs", proto = ":connection_proto")`
   emits `libconnection_proto-*.rlib`, and Rust writes
   `connection_proto::fastverk::v1`. The fix is one line:
   `pub use connection_proto::fastverk::v1 as proto;`. Every existing
   `crate::proto::{...}` keeps compiling through the re-export. ⭐ Blast radius:
   one line.

### 7.2 ⭐ Two toolchains from one proto

This is the resolution to §6.2's async problem, and it is the one non-obvious
decision in the whole migration.

| Consumer | Toolchain | Gets |
|---|---|---|
| `credresolve`, `cred-helper` | a **tonic-free** `rust_prost_toolchain` (copy `tomato-bazel/gate`'s `//proto:prost_toolchain` verbatim) | messages only — no tonic, no tokio, no mio, no socket2 in the per-URI binary |
| the hub, any remote store | `@rules_rust_prost//:default_prost_toolchain` | messages **and** tonic client/server |

Verified against `rules_rust 0.70.0`: `default_prost_toolchain_impl` does set
`tonic_plugin`, `tonic_plugin_flag`, and `tonic_runtime` — so the default gives
you tonic, and `gate`'s and `truss`'s comments are correct on this point.
⚠ `governor/MODULE.bazel:74` states the opposite ("default_prost_toolchain is
prost-only and carries no tonic plugin"); that comment is stale and should not
be copied.

⛔ **Trap correction, and it inverts the brief.** The "declare `prost-types` as an
unused workspace-member dep or you get `no such target '@…_crates//:prost-types'`
at analysis" trap applies **only when you define your own
`rust_prost_toolchain`** — the default one supplies
`//private/3rdparty/crates:prost-types` itself. So:

- take the default toolchain only → ✅ the trap does **not** apply
- ⭐ take the split above (which this review recommends) → ⛔ **the trap applies**,
  and `credresolve/Cargo.toml` needs, verbatim from gate's practice:

  ```toml
  # Declared, not used. `rust_prost_toolchain` requires a `prost_types` target,
  # and nothing generated here references it.
  prost-types.workspace = true
  ```

⚠ The tonic-free toolchain must be registered so it **outranks**
`@rules_rust_prost`'s default. A root-module registration resolves first, so
this works — and gate registers it `dev_dependency = True` for the separate,
correct reason that a non-dev `register_toolchains` propagates a Rust toolchain
onto every consumer of the module. ⚠ `fastverk_credresolve` **is** consumed as a
`bazel_dep` (by `fvkit`), so follow gate exactly here.

⚠ Also check while in `MODULE.bazel`: `use_repo(crate, "crates")` claims the
generic repo name `crates`, and `credresolve/BUILD.bazel` loads `@crates//:defs.bzl`.
`isolate = True` mitigates the collision; gate's practice (namespacing the repo
`gate_crates`) is stronger and costs one rename.

### 7.3 `rules_aip` — adopt, with reported conflicts

Pin **0.3.0** (in the registry; `brando`/`governor`/`truss` are on 0.2.2).
⚠ It carries `protobuf 33.4`, which **matches this repo's pin** — so the
hardcoded-protoc churn this ruleset has caused before should not bite. Copy
`governor/proto/governor/v1/BUILD.bazel`'s wiring: it is the closest shape (an
internal RPC contract, not a public resource API) and it already documents each
disabled rule with a reason.

⭐ AIP is right about some of this and wrong about some of it. **Reported, not
silently applied:**

| AIP rule | Call | Reason |
|---|---|---|
| `0131` standard `Get` | ⭐ **adopt the naming** | `GetSecretRequest`/`GetSecretResponse` is free and better than an ad-hoc name. |
| `0123::resource-annotation` — make `SecretRef` a resource with a name string | ⛔ **push back, disable** | AIP wants `keychains/fastverk.github/secrets/oauth`. That stringly-types the ref and destroys the typed `oneof` that makes `SecretStore::handles()` exhaustive at compile time. ⭐ Exhaustiveness is the property that keeps a *credential reader* honest; a resource-name string is not worth trading it for. |
| `0158` pagination on any `List` | ⛔ **disable, with the estate's reason** | This estate has been bitten twice by pagination fields that were accepted and ignored (`liststatements-ignores-page-token`, `entity-list-cursor-does-not-advance`). Pagination fields that do not work are worse than none. |
| `0203::field-behavior-required` | ⭐ **adopt** | `google.api.field_behavior` genuinely documents which fields a store must receive. Cheap, real value. |
| `0142::time-field-type` | ⭐ **adopt** | `expires_at` should be `google.protobuf.Timestamp`, not the RFC-3339 `String` `ResolvedCred` carries today. ⚠ Note the pleasing consequence: Bazel's wire format wants an RFC-3339 *string*, so the conversion happens at the Bazel boundary — exactly where a protocol-specific format belongs. |
| `0127::http-annotation` | disable | gRPC only, no REST transcoding. |
| `0191::java-*` | disable | Rust only. |
| `0122::name-suffix` (`Connection.id` → `name`) | ⚠ disable | Tag 1 is unchanged so it is wire-compatible with the persisted `connections.pb`, but it churns every Rust reference for no behavioral gain. |

### 7.4 What becomes a proto, and ⚠ what must stay Rust

The rule is **"DTOs are protos," not "everything is a proto."** A review that
proto-ized behavior would be worse than the status quo.

**→ proto** (crosses a process, language, or file boundary):

- `ResolvedCred` (`connections.rs:78`) — ⭐ it crosses the process boundary into
  Bazel as JSON, and would cross the hub boundary. `header`, `value`,
  `expires_at: google.protobuf.Timestamp`.
- `GetSecretRequest` / `GetSecretResponse` — the store service contract.
- The config-arm schema (`config.rs`'s hand-parsed `serde_json::Value`) — ⭐ this
  one is overdue. It is rendered by the operator from a `CredentialSet` CRD and
  consumed here, i.e. a cross-repo, cross-language interchange format currently
  defined by neither side. Proto with a JSON mapping.
- Already proto and correct: `SecretRef`, `KeychainRef`, `EnvRef`, `FileRef`,
  `OAuthConfig`, `Connection`, `ConnectionRegistry`, `AuthKind`.

**⚠ → stays Rust** (behavior or process-local state, never serialized):

- `KeychainStore`, `EnvStore`, `FileStore` — unit structs. **Behavior, not
  data.** There is nothing to serialize; a proto here would be an empty message
  pretending to be a type.
- `SecretStore` — the in-process dispatch trait. The proto `service` is the
  *contract*; this is one implementation shape of it. ⚠ Keeping both means they
  are kept aligned by convention rather than by the compiler — that is the
  honest cost of avoiding tokio in the hot path, and it should be stated in the
  code, not discovered.
- `Resolver` — ordered backend list, process-local.
- `Args` (`oidc/src/main.rs:32`) — CLI parsing.
- `ResolvedCred`'s *construction sites* — the proto is the wire type; the
  builders stay Rust.

---

## 8 · Sequence

⚠ Three repos consume this by pinned `url` + `sha256`
(`aion-mono` ×3 blocks, `setup-tbzl`, the CI image, five ConfigSet org
manifests). Any step that changes the binary needs a release and a coordinated
re-pin. The sequence below is ordered so **the highest-value step is also the
one with the smallest blast radius**, and so nothing depends on a step that has
not landed.

| # | Step | Breaks consumers? | Notes |
|---|---|---|---|
| **0** | ✅ **Remove BuildBuddy from this repo's build config** | ❌ no — build config only | *Shipped in the companion PR.* Lets the key be **deleted**, not rotated. |
| **1** | ⭐⭐ **Fail-open fix behind `FASTVERK_CRED_STRICT=1`** ([§2.3](#23--the-fix-claimed-vs-unclaimed)) | ❌ **no** — opt-in, default unchanged | ⭐ **Land this first.** Highest value, additive, no consumer action. `setup-tbzl` asks for this flag by name. |
| **2** | `cred-helper doctor` + publish `linux-arm64` + publish `fastverk-oidc` | ❌ no — new subcommand, new assets | Unblocks `setup-tbzl` ([F-5](#f-5--no-linux-arm64-artifact), [F-4](#f-4--fastverk-oidc-is-built-and-tested-but-never-published)) and gives §2.4 its home. |
| **3** | Fix precedence: arms above presets ([F-3](#f-3--config-arms-can-never-override-a-built-in-preset)) | ⚠ **behavior change** | A host with both an arm and an env var now resolves via the arm. Correct, but it must be released deliberately, not folded into another step. |
| **4** | ⭐ **Bazelify codegen**: delete `build.rs`, `proto_library` + two prost toolchains ([§7.1](#71--the-current-codegen-path-is-the-defect)–[§7.2](#72--two-toolchains-from-one-proto)) | ❌ no — bytes may differ, behavior identical | Pure build-system change. ⚠ Do it *before* any proto grows a `service`, so the service arrives on working machinery instead of debugging both at once. |
| **5** | `rules_aip` + lint, conflicts resolved per [§7.3](#73--rules_aip--adopt-with-reported-conflicts); `ResolvedCred` → proto | ❌ no | Adds `//proto/...:aip_lint` to `bazel test //...`. |
| **6** | Define the `SecretStore` proto `service`; in-process impls unchanged | ❌ no — nothing serves it yet | ⭐ The contract lands with **no runtime risk**. This is the cheap half of the redesign and it can sit here indefinitely. |
| **7** | Client-credentials secret source ([§5.5](#55--the-ps-aux-claim--confirmed-and-worse-than-reported)) | ⚠ new capability | ⭐ Deletes four hand-rolled shell refresh loops and closes the argv exposure. Background-refresher shape only — never synchronous in `get`. |
| **8** | Hub, per-pod sidecar, remote stores behind it ([§6.4](#64--the-shape-if-it-is-built)) | ⚠ new deployment dep for CI; **none locally** | ⛔ **Blocked on step 1.** Do not build this while "hub down" and "host is anonymous" are the same observable. |

⭐ Steps 0–2 are additive and independently valuable; steps 4–6 are pure
build/contract work with no runtime risk; only 3, 7, and 8 change behavior.
**A design that can only arrive all at once is much less useful than one that
can arrive in eight steps, six of which break nothing.**

---

## 9 · What this review did not do

- ⛔ **No secret was rotated, deleted, read, or written.** The leaked key is
  in-tree in two other repositories (`tomato-bazel/tbzl-profile` and one
  `tomato-bazel/infra` doc). Retiring it is what [F-2](#f-2--the-buildbuddy-remote-cache-never-served-a-single-hit)
  makes possible; ⚠ **purging it from those repos' history is separate work and
  is not addressed here.** It is not this repo's to do, and it must be done.
- ⛔ **No fixture, test vector, or example in this repository contains a real
  credential.** The strings used in tests (`s3cr3t`, `glpat-xyz`,
  `QVdTOnBhc3N3b3Jk` = `base64("AWS:password")`) are placeholders and were
  already so. The companion PR adds a `sh_test` that fails if a secret-shaped
  value ever reaches a command-line flag in the build config — it is verified
  against the pre-fix `release.yml`, where it fails on the exact line that
  leaked, so it is not inert.
- ⚠ **Checked and correct, so nobody re-flags it:** `connections.rs:237` bundles
  a literal GitHub OAuth client id. It is a **device-code** client id, which
  carries no secret and is publicly discoverable via `/apps/{slug}` — the
  comment beside it already says so, accurately. It is not a credential and
  must not be treated as one.
- ⛔ **BuildBuddy remains in the source.** It is a supported connection type
  with a live consumer. Only this repo's *own* use of BuildBuddy as a remote
  cache was removed.
- Nothing was deployed. No consumer was re-pinned.
