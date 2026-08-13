//! The connection registry: the host → auth mapping the credential
//! helper consults and the GUI manages.
//!
//! Persisted as a prost-encoded [`ConnectionRegistry`] at
//! [`crate::paths::registry_path`]. Secrets are never stored here — only
//! a keychain reference. [`resolve`] is the read path the cred-helper
//! (and `fvd`'s `GetCredentials`) use to turn a request URI into a
//! header + value.

use anyhow::{bail, Context, Result};
use prost::Message;

use crate::proto::{AuthKind, Connection, ConnectionRegistry, OAuthConfig};
use crate::{paths, secretstore, uri};

/// Load the persisted registry, or an empty one when none exists.
pub fn load() -> Result<ConnectionRegistry> {
    let p = paths::registry_path()?;
    if !p.exists() {
        return Ok(ConnectionRegistry::default());
    }
    let bytes = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    let mut reg =
        ConnectionRegistry::decode(bytes.as_slice()).context("decode connection registry")?;
    migrate(&mut reg);
    Ok(reg)
}

/// Migrate registries written before secret backends were pluggable: a
/// connection with no `secret_refs` but a legacy `keychain_service` gets a
/// single keychain ref synthesized so its stored token keeps resolving.
fn migrate(reg: &mut ConnectionRegistry) {
    for c in &mut reg.connections {
        if c.secret_refs.is_empty() && !c.keychain_service.is_empty() {
            let account = if c.keychain_account.is_empty() {
                "oauth".to_string()
            } else {
                c.keychain_account.clone()
            };
            c.secret_refs = vec![secretstore::keychain_ref(c.keychain_service.clone(), account)];
        }
    }
}

/// Persist the registry.
pub fn save(reg: &ConnectionRegistry) -> Result<()> {
    paths::ensure_config_dir()?;
    let p = paths::registry_path()?;
    std::fs::write(&p, reg.encode_to_vec()).with_context(|| format!("write {}", p.display()))
}

/// Remove a connection by id; returns whether one was removed. The
/// caller is responsible for deleting any associated keychain item.
pub fn remove(reg: &mut ConnectionRegistry, id: &str) -> bool {
    let before = reg.connections.len();
    reg.connections.retain(|c| c.id != id);
    reg.connections.len() != before
}

/// The first connection whose host patterns match `host`.
#[must_use]
pub fn match_host<'a>(reg: &'a ConnectionRegistry, host: &str) -> Option<&'a Connection> {
    reg.connections
        .iter()
        .find(|c| c.host_patterns.iter().any(|p| host_matches(p, host)))
}

/// `*.suffix` matches `suffix` and any `*.suffix`; otherwise exact.
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    pattern.strip_prefix("*.").map_or_else(
        || pattern == host,
        |suffix| host == suffix || host.ends_with(&format!(".{suffix}")),
    )
}

/// A resolved credential ready to emit as a Bazel cred-helper header.
pub struct ResolvedCred {
    pub header: String,
    pub value: String,
    /// When Bazel should re-invoke the helper for this host (RFC 3339 UTC), or
    /// `None` to let Bazel cache it for the build. Set only for a *refreshable*
    /// source (a token file, see `host_file_token`): a long build outlives a
    /// short-lived token, so Bazel must re-read the file periodically rather
    /// than cache the first value forever. Env/keychain secrets are static, so
    /// they leave this `None` and behave exactly as before.
    pub expires: Option<String>,
}

/// Resolve the auth header for a request URI. `None` => anonymous fetch.
///
/// Matches the request host against the user's registry first, then the
/// built-in [`default_registry`] (github.com / gitlab.com), then
/// a generic per-host env convention. A matched connection's `secret_refs`
/// are tried in order (keychain locally, the canonical env var in CI) via the
/// [`secretstore::Resolver`]. Best-effort: a corrupt registry or a keychain
/// error degrades to the next option / anonymous rather than failing the
/// build. Does NOT refresh expired tokens.
pub fn resolve(req_uri: &str) -> Result<Option<ResolvedCred>> {
    let host = uri::host_of(req_uri);
    if host.is_empty() {
        return Ok(None);
    }
    // Refreshable per-host fallback, checked FIRST because it is the only source
    // that survives a long build: `FASTVERK_TOKEN_FILE_<HOST>` points at a file
    // whose contents a producer (e.g. the build-runner's token-refresh loop)
    // rewrites in place. We read it fresh on every invocation and tell Bazel to
    // re-invoke us before the token's TTL, so a build longer than the token
    // lifetime keeps working instead of dying UNAUTHENTICATED mid-way. See
    // aion-idp-build-rbe-token-expiry.
    if let Some(secret) = host_file_token(host) {
        return Ok(Some(ResolvedCred {
            header: "Authorization".to_string(),
            value: format!("Bearer {secret}"),
            expires: Some(rfc3339_utc(now_secs() + file_token_ttl_secs())),
        }));
    }
    // User registry wins; the built-in defaults fill in on a miss (or when
    // there's no registry file at all, e.g. CI).
    let reg = load().unwrap_or_default();
    let conn = match_host(&reg, host).cloned().or_else(|| {
        let def = default_registry();
        match_host(&def, host).cloned()
    });
    if let Some(conn) = conn {
        if let Some(secret) = secretstore::Resolver::standard().resolve(&conn.secret_refs) {
            return Ok(Some(ResolvedCred {
                header: conn.header.clone(),
                value: format!("{}{secret}", conn.value_prefix),
                expires: None,
            }));
        }
    }
    // Generic per-host fallback: for any host without a matching connection
    // (or whose connection has no stored secret), emit `Authorization: Bearer`
    // when `FASTVERK_TOKEN_<HOST>` is set. Lets a consumer authenticate an
    // arbitrary host (e.g. a self-hosted GitLab) with one env var — no
    // registry entry, and nothing host-specific baked into this tool.
    if let Some(secret) = host_env_token(host) {
        return Ok(Some(ResolvedCred {
            header: "Authorization".to_string(),
            value: format!("Bearer {secret}"),
            expires: None,
        }));
    }
    Ok(None)
}

/// The refreshable per-host token file (`FASTVERK_TOKEN_FILE_<sanitized host>`),
/// read fresh and trimmed. The env var holds the FILE PATH, not the secret, so a
/// producer can rewrite the file's contents without the reader's environment
/// (frozen at process start) ever going stale. Empty path, missing/unreadable
/// file, or empty contents all yield `None` (degrade to the next source).
fn host_file_token(host: &str) -> Option<String> {
    let path = std::env::var(canonical_env_var(host).replace("FASTVERK_TOKEN_", "FASTVERK_TOKEN_FILE_"))
        .ok()
        .filter(|p| !p.is_empty())?;
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// How long a file-sourced token is advertised as valid (seconds), overridable
/// via `FASTVERK_TOKEN_FILE_TTL_SECS`. Kept SHORT (default 600s) so Bazel
/// re-reads the file well within a real token's lifetime; the producer refresh
/// loop only needs to rewrite the file faster than the *real* token expires.
fn file_token_ttl_secs() -> u64 {
    std::env::var("FASTVERK_TOKEN_FILE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&s| s > 0)
        .unwrap_or(600)
}

/// Seconds since the Unix epoch (0 if the clock is before it — impossible in
/// practice, and harmless here since it only shortens the advertised TTL).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format Unix-epoch seconds as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`),
/// which is the format Bazel's credential-helper protocol expects for `expires`.
/// Civil-from-days is Howard Hinnant's algorithm (valid for all Gregorian dates);
/// hand-rolled to keep credresolve dependency-light (no chrono/time).
fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 -> civil (year, month, day)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// The generic per-host env var (`FASTVERK_TOKEN_<sanitized host>`), if set
/// and non-empty. E.g. `git.example.com` -> `FASTVERK_TOKEN_GIT_EXAMPLE_COM`.
fn host_env_token(host: &str) -> Option<String> {
    std::env::var(canonical_env_var(host))
        .ok()
        .filter(|v| !v.is_empty())
}

/// The built-in connections — GitHub and GitLab — each carrying a
/// keychain ref and the canonical/alias env refs. Used as the fallback when
/// a host isn't in the user's registry (notably CI, which has no registry
/// file and resolves the env backend). This replaces the old hand-rolled
/// host→env table that lived in the cred-helper.
#[must_use]
pub fn default_registry() -> ConnectionRegistry {
    let mut reg = ConnectionRegistry::default();
    for provider in ["github", "gitlab"] {
        if let Ok(c) = preset(provider, "", "") {
            reg.connections.push(c);
        }
    }
    reg
}

// ─── Provider presets ──────────────────────────────────────────────

/// Built-in (public) OAuth App client id shipped with the app, so users can
/// connect GitHub with one click — no per-machine configuration. Device-code
/// client ids carry NO secret, so bundling is safe. An explicit `--client-id`
/// overrides it. Other providers/instances supply their own `--client-id`.
const GITHUB_CLIENT_ID: &str = "Ov23lioy3u3aCHYDK8IJ";

/// `given` if non-empty, else the bundled `default`.
fn pick(given: &str, default: &str) -> String {
    if given.is_empty() { default } else { given }.to_string()
}

/// The default instance host for a provider when none is given.
fn default_host(provider: &str) -> &'static str {
    match provider {
        "github" => "github.com",
        "gitlab" => "gitlab.com",
        _ => "",
    }
}

/// Bundled (public) OAuth client id for a specific (provider, host), or ""
/// for instances we don't ship one for (the user supplies `--client-id`).
fn default_client_id(provider: &str, host: &str) -> &'static str {
    if provider == "github" && host == "github.com" {
        GITHUB_CLIENT_ID
    } else {
        ""
    }
}

/// Stable connection id: the short provider name for its default host, the
/// instance host otherwise (so multiple instances of one provider coexist
/// — github.com vs github.acme.com vs a self-hosted gitlab.example.com).
fn connection_id(provider: &str, host: &str) -> String {
    if host == default_host(provider) {
        provider.to_string()
    } else {
        host.to_string()
    }
}

/// Build a connection from a provider preset for a given instance `host`
/// (empty = the provider default). OAuth `client_id` falls back to the
/// bundled id for known (provider, host) pairs. The same provider can be
/// connected one-by-one across hosted / enterprise / self-hosted hosts.
pub fn preset(provider: &str, host: &str, client_id: &str) -> Result<Connection> {
    let host = if host.is_empty() {
        default_host(provider)
    } else {
        host
    };
    let id = connection_id(provider, host);
    let mut c = Connection::default();
    match provider {
        "github" => {
            let canonical = host == "github.com";
            c.display_name = if canonical {
                "GitHub".to_string()
            } else {
                format!("GitHub ({host})")
            };
            c.provider = "github".to_string();
            // github.com has dedicated raw/codeload hosts; GHE serves all
            // from the instance host.
            c.host_patterns = if canonical {
                vec![
                    "github.com".to_string(),
                    "*.github.com".to_string(),
                    "raw.githubusercontent.com".to_string(),
                    "codeload.github.com".to_string(),
                ]
            } else {
                vec![host.to_string(), format!("*.{host}")]
            };
            c.header = "Authorization".to_string();
            c.value_prefix = "Bearer ".to_string();
            c.auth_kind = AuthKind::Oauth as i32;
            c.oauth = Some(OAuthConfig {
                client_id: pick(client_id, default_client_id("github", host)),
                auth_url: format!("https://{host}/login/oauth/authorize"),
                token_url: format!("https://{host}/login/oauth/access_token"),
                device_auth_url: format!("https://{host}/login/device/code"),
                scopes: vec!["repo".to_string(), "read:org".to_string()],
                ..Default::default()
            });
        }
        "gitlab" => {
            c.display_name = format!("GitLab ({host})");
            c.provider = "gitlab".to_string();
            c.host_patterns = vec![host.to_string(), format!("*.{host}")];
            c.header = "Authorization".to_string();
            c.value_prefix = "Bearer ".to_string();
            c.auth_kind = AuthKind::Oauth as i32;
            c.oauth = Some(OAuthConfig {
                client_id: pick(client_id, default_client_id("gitlab", host)),
                auth_url: format!("https://{host}/oauth/authorize"),
                token_url: format!("https://{host}/oauth/token"),
                device_auth_url: format!("https://{host}/oauth/authorize_device"),
                scopes: vec!["api".to_string(), "read_repository".to_string()],
                ..Default::default()
            });
        }
        // ⛔ THERE IS NO `buildbuddy` PRESET ANY MORE, AND ITS ABSENCE IS THE POINT.
        // It resolved remote.buildbuddy.io -> `x-buildbuddy-api-key` from
        // $BUILDBUDDY_API_KEY. That key was committed to a PUBLIC repository on
        // 2026-08-05 carrying CACHE-WRITE, so the exposure was cache poisoning, and the
        // estate removed BuildBuddy rather than rotating a key for a service it does not
        // need. Deleting the callers left the CAPABILITY intact: anything that set the env
        // var would have re-armed it silently. Deleting the preset is what makes it
        // impossible. Do not re-add one.
        other => bail!("unknown provider preset: {other} (use github|gitlab)"),
    }
    // Where this connection's secret lives, in precedence order: the
    // keychain locally, then the canonical env var (+ provider/host alias
    // names) for CI/automation. Secrets never live in the registry itself.
    // ⚠ Every remaining preset is OAuth. This was a conditional while an api-key provider
    // existed; it is not one now, and a future api-key provider should reintroduce the
    // branch deliberately rather than inherit it.
    let account = "oauth";
    c.secret_refs = vec![
        secretstore::keychain_ref(format!("fastverk.{id}"), account),
        secretstore::env_ref(canonical_env_var(&id), env_aliases(provider)),
    ];
    c.id = id;
    Ok(c)
}

/// Canonical env var for a connection id: id "github" ->
/// "FASTVERK_TOKEN_GITHUB", "gitlab.example.com" ->
/// "FASTVERK_TOKEN_GITLAB_EXAMPLE_COM" (non-alphanumerics become `_`).
fn canonical_env_var(id: &str) -> String {
    let suffix: String = id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("FASTVERK_TOKEN_{suffix}")
}

/// Standard ecosystem env var aliases for a provider, tried after the
/// canonical `FASTVERK_TOKEN_<id>` var (first non-empty wins). These are the
/// widely-used names only — nothing org- or instance-specific (a self-hosted
/// instance authenticates via the canonical/host env var or a connection).
fn env_aliases(provider: &str) -> Vec<String> {
    match provider {
        "github" => vec!["GITHUB_TOKEN", "GH_TOKEN"],
        "gitlab" => vec!["GITLAB_TOKEN"],
        _ => vec![],
    }
    .into_iter()
    .map(String::from)
    .collect()
}

// `connect`/`disconnect` (OAuth device flow, keychain writes) live in fvkit
// on top of this resolve core — credresolve owns only the registry schema +
// the read/resolve path + the secret backends, so the contract lives once.

#[cfg(test)]
mod tests {
    use super::{
        canonical_env_var, default_registry, env_aliases, host_matches, match_host, preset,
    };
    use crate::proto::{secret_ref::Store, AuthKind};

    /// The keychain item a preset pins its secret to (first keychain ref).
    fn keychain_of(c: &crate::proto::Connection) -> (&str, &str) {
        c.secret_refs
            .iter()
            .find_map(|r| match &r.store {
                Some(Store::Keychain(k)) => Some((k.service.as_str(), k.account.as_str())),
                _ => None,
            })
            .expect("a keychain secret ref")
    }

    #[test]
    fn wildcard_and_exact() {
        assert!(host_matches("github.com", "github.com"));
        assert!(!host_matches("github.com", "api.github.com"));
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(host_matches("*.github.com", "github.com"));
        assert!(!host_matches("*.github.com", "notgithub.com"));
    }

    #[test]
    fn presets_have_expected_shape() {
        // Default GitHub host.
        let gh = preset("github", "", "cid123").unwrap();
        assert_eq!(gh.id, "github");
        assert_eq!(gh.auth_kind(), AuthKind::Oauth);
        assert_eq!(gh.header, "Authorization");
        assert_eq!(gh.oauth.as_ref().unwrap().client_id, "cid123");
        assert!(gh.host_patterns.iter().any(|h| h == "github.com"));

        // GitHub Enterprise instance: distinct id, host-derived endpoints.
        let ghe = preset("github", "github.acme.com", "ent").unwrap();
        assert_eq!(ghe.id, "github.acme.com");
        assert_eq!(keychain_of(&ghe), ("fastverk.github.acme.com", "oauth"));
        assert!(ghe.host_patterns.iter().any(|h| h == "github.acme.com"));
        assert_eq!(
            ghe.oauth.as_ref().unwrap().device_auth_url,
            "https://github.acme.com/login/device/code"
        );

        // GitLab default (public instance) + an arbitrary self-hosted one.
        let gl = preset("gitlab", "", "").unwrap();
        assert_eq!(gl.id, "gitlab");
        assert!(gl.host_patterns.iter().any(|h| h == "gitlab.com"));
        let gl2 = preset("gitlab", "gitlab.example.com", "x").unwrap();
        assert_eq!(gl2.id, "gitlab.example.com");

        assert!(preset("nope", "", "").is_err());
    }

    /// Canonical env naming + the standard alias table + the default registry,
    /// hermetically (no secret reads).
    #[test]
    fn env_refs_and_default_registry() {
        assert_eq!(canonical_env_var("github"), "FASTVERK_TOKEN_GITHUB");
        assert_eq!(
            canonical_env_var("gitlab.example.com"),
            "FASTVERK_TOKEN_GITLAB_EXAMPLE_COM"
        );

        // GitHub preset carries the canonical var + ecosystem aliases.
        let gh = preset("github", "", "").unwrap();
        let env = gh
            .secret_refs
            .iter()
            .find_map(|r| match &r.store {
                Some(Store::Env(e)) => Some(e),
                _ => None,
            })
            .expect("an env secret ref");
        assert_eq!(env.name, "FASTVERK_TOKEN_GITHUB");
        assert!(env.aliases.iter().any(|a| a == "GITHUB_TOKEN"));
        assert!(env.aliases.iter().any(|a| a == "GH_TOKEN"));

        // GitLab: Bearer header; the standard GITLAB_TOKEN alias.
        let gl = preset("gitlab", "", "").unwrap();
        assert_eq!(gl.header, "Authorization");
        assert_eq!(gl.value_prefix, "Bearer ");
        assert!(env_aliases("gitlab").iter().any(|a| a == "GITLAB_TOKEN"));

        // The default registry covers the public provider hosts.
        let def = default_registry();
        assert!(match_host(&def, "github.com").is_some());
        assert!(match_host(&def, "gitlab.com").is_some());
    }

    /// The generic per-host fallback: an arbitrary host (e.g. a self-hosted
    /// GitLab not in the default registry) is auth-able via FASTVERK_TOKEN_<HOST>
    /// with NO host-specific code. Pure env, hermetic.
    #[test]
    fn host_env_fallback() {
        assert_eq!(
            canonical_env_var("git.example.com"),
            "FASTVERK_TOKEN_GIT_EXAMPLE_COM"
        );
        let var = "FASTVERK_TOKEN_GIT_EXAMPLE_COM";
        std::env::remove_var(var);
        assert_eq!(super::host_env_token("git.example.com"), None);
        std::env::set_var(var, "tok");
        assert_eq!(super::host_env_token("git.example.com").as_deref(), Some("tok"));
        std::env::remove_var(var);
    }

    #[test]
    fn rfc3339_utc_formats_known_epochs() {
        use super::rfc3339_utc;
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339_utc(1_735_689_600), "2025-01-01T00:00:00Z"); // leap-year boundary
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z"); // Feb 29 (leap day)
        assert_eq!(rfc3339_utc(1_709_251_200), "2024-03-01T00:00:00Z"); // day after the leap day
        assert_eq!(rfc3339_utc(59), "1970-01-01T00:00:59Z"); // seconds field
        assert_eq!(rfc3339_utc(3661), "1970-01-01T01:01:01Z"); // h/m/s split
    }

    #[test]
    fn host_file_token_reads_the_file_fresh_and_resolve_sets_expires() {
        use std::io::Write;
        // Unique path so the test doesn't collide with a real registry or another run.
        let path = std::env::temp_dir().join(format!("credresolve-filetok-{}", std::process::id()));
        let var = "FASTVERK_TOKEN_FILE_RBE_EXAMPLE_COM";
        std::env::remove_var(var);

        // No env var -> None.
        assert_eq!(super::host_file_token("rbe.example.com"), None);

        std::env::set_var(var, &path);
        // Env var set but file absent -> None (degrade, don't error).
        let _ = std::fs::remove_file(&path);
        assert_eq!(super::host_file_token("rbe.example.com"), None);

        // File present -> its trimmed contents, read fresh each call.
        std::fs::File::create(&path).unwrap().write_all(b"  tok-v1\n").unwrap();
        assert_eq!(super::host_file_token("rbe.example.com").as_deref(), Some("tok-v1"));
        std::fs::File::create(&path).unwrap().write_all(b"tok-v2").unwrap();
        assert_eq!(super::host_file_token("rbe.example.com").as_deref(), Some("tok-v2"));

        // resolve() picks it up as a Bearer with an `expires` set (refreshable).
        let c = super::resolve("https://rbe.example.com/foo").unwrap().unwrap();
        assert_eq!(c.header, "Authorization");
        assert_eq!(c.value, "Bearer tok-v2");
        assert!(c.expires.is_some(), "a file-sourced token must advertise an expiry");

        std::env::remove_var(var);
        let _ = std::fs::remove_file(&path);
    }
}
