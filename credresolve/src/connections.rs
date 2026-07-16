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
}

/// Resolve the auth header for a request URI. `None` => anonymous fetch.
///
/// Matches the request host against the user's registry first, then the
/// built-in [`default_registry`] (github.com / gitlab.com / buildbuddy), then
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
            }));
        }
    }
    // Config-driven match arms (the CI / CredentialSet path): host→auth supplied
    // as data (a mounted credentials.json), not baked into this binary. Covers
    // hosts the built-in defaults don't — a private ECR mirror, a self-hosted
    // forge — each with a compiled-in secret source (env / file / minted ECR).
    if let Some(c) = crate::config::resolve_host(host) {
        return Ok(Some(c));
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
        }));
    }
    Ok(None)
}

/// The generic per-host env var (`FASTVERK_TOKEN_<sanitized host>`), if set
/// and non-empty. E.g. `git.example.com` -> `FASTVERK_TOKEN_GIT_EXAMPLE_COM`.
fn host_env_token(host: &str) -> Option<String> {
    std::env::var(canonical_env_var(host))
        .ok()
        .filter(|v| !v.is_empty())
}

/// The built-in connections — GitHub, GitLab, BuildBuddy — each carrying a
/// keychain ref and the canonical/alias env refs. Used as the fallback when
/// a host isn't in the user's registry (notably CI, which has no registry
/// file and resolves the env backend). This replaces the old hand-rolled
/// host→env table that lived in the cred-helper.
#[must_use]
pub fn default_registry() -> ConnectionRegistry {
    let mut reg = ConnectionRegistry::default();
    for provider in ["github", "gitlab", "buildbuddy"] {
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
        "buildbuddy" => "remote.buildbuddy.io",
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
        "buildbuddy" => {
            // BuildBuddy authenticates with a static API key (no OAuth).
            c.display_name = "BuildBuddy".to_string();
            c.provider = "buildbuddy".to_string();
            c.host_patterns = vec![host.to_string()];
            c.header = "x-buildbuddy-api-key".to_string();
            c.auth_kind = AuthKind::ApiKey as i32;
        }
        other => bail!("unknown provider preset: {other} (use github|gitlab|buildbuddy)"),
    }
    // Where this connection's secret lives, in precedence order: the
    // keychain locally, then the canonical env var (+ provider/host alias
    // names) for CI/automation. Secrets never live in the registry itself.
    let account = if provider == "buildbuddy" { "api-key" } else { "oauth" };
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
        "buildbuddy" => vec!["BUILDBUDDY_API_KEY"],
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

        let bb = preset("buildbuddy", "", "").unwrap();
        assert_eq!(bb.auth_kind(), AuthKind::ApiKey);
        assert_eq!(bb.header, "x-buildbuddy-api-key");
        assert_eq!(keychain_of(&bb), ("fastverk.buildbuddy", "api-key"));

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
}
