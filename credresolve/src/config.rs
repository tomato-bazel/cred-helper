//! Config-driven credential match arms — the CI / build path.
//!
//! A `CredentialSet` (build.tbzl.dev) renders its arms into a JSON file the
//! build's `ConfigSet` mounts alongside the bazelrc. Each arm maps host
//! patterns to a header + value, drawing the secret from a *compiled-in*
//! source (an env var, a file, or a minted AWS-ECR token). This is the "the
//! match arms come from configuration, not baked into the binary" layer: it
//! sits between the user's keychain registry and the built-in provider
//! defaults, so a build authenticates an arbitrary registry — a self-hosted
//! GitLab, a private ECR mirror — by data alone, nothing host-specific in the
//! tool.
//!
//! Security: the config SELECTS a secret source and supplies its parameters
//! (an env name, a file path, an ECR region); the behavior of each source is
//! compiled in. There is no "run this command" source — never config-injected
//! code, exactly like [`crate::secretstore`].
//!
//! Parsed with `serde_json::Value` (no serde-derive) — the schema is small and
//! the file is read once per invocation, off the per-char URI hot path.

use serde_json::Value;

use crate::connections::{host_matches, ResolvedCred};

/// Where the rendered arms live: `$FASTVERK_CRED_CONFIG`, else
/// `<config_dir>/credentials.json`. The build-runner points the env at the
/// ConfigSet mount (`/etc/fastverk/config/credentials.json`); locally it falls
/// back to the fastverk config dir (usually absent → no config arms).
fn config_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("FASTVERK_CRED_CONFIG") {
        return (!p.is_empty()).then(|| std::path::PathBuf::from(p));
    }
    crate::paths::config_dir()
        .ok()
        .map(|d| d.join("credentials.json"))
}

/// Resolve `host` against the configured arms. `None` = no arm matched, or the
/// matched arm's secret is unavailable — the caller falls through to the
/// built-in defaults / generic env fallback. Best-effort: a missing or
/// malformed config file is a miss, never an error (a build degrades to
/// anonymous rather than failing the fetch).
#[must_use]
pub fn resolve_host(host: &str) -> Option<ResolvedCred> {
    let raw = std::fs::read_to_string(config_path()?).ok()?;
    resolve_in(&raw, host)
}

/// The pure core of [`resolve_host`]: match `host` against the arms in the
/// JSON document `raw`. Split out so it's testable without touching the
/// filesystem or env layout.
fn resolve_in(raw: &str, host: &str) -> Option<ResolvedCred> {
    let doc: Value = serde_json::from_str(raw).ok()?;
    doc.get("arms")?
        .as_array()?
        .iter()
        .filter(|arm| arm_matches(arm, host))
        .find_map(|arm| resolve_arm(arm, host))
}

/// Whether any of an arm's `hostPatterns` matches `host` (same `*.suffix` /
/// exact semantics as the connection registry).
fn arm_matches(arm: &Value, host: &str) -> bool {
    arm.get("hostPatterns")
        .and_then(Value::as_array)
        .is_some_and(|ps| {
            ps.iter()
                .filter_map(Value::as_str)
                .any(|p| host_matches(p, host))
        })
}

/// Turn a matched arm into a resolved header, or `None` if its secret can't be
/// read (so a later arm — or the built-in fallback — still gets a chance).
fn resolve_arm(arm: &Value, host: &str) -> Option<ResolvedCred> {
    let header = arm
        .get("header")
        .and_then(Value::as_str)
        .unwrap_or("Authorization")
        .to_string();
    let prefix = arm.get("valuePrefix").and_then(Value::as_str).unwrap_or("");
    let secret = resolve_secret(arm.get("secret")?, host)?;
    Some(ResolvedCred {
        header,
        value: format!("{prefix}{secret}"),
        // The config-file path does not advertise refresh yet; a file-secret arm
        // that needs it would set this the same way connections::resolve does.
        expires: None,
        warning: None,
    })
}

/// The compiled-in secret sources, selected by the arm's `secret` object shape:
/// `{"env":{…}}`, `{"file":{…}}`, or `{"awsEcr":{…}}`.
fn resolve_secret(secret: &Value, host: &str) -> Option<String> {
    if let Some(env) = secret.get("env") {
        resolve_env(env)
    } else if let Some(file) = secret.get("file") {
        resolve_file(file)
    } else if let Some(ecr) = secret.get("awsEcr") {
        ecr::authorization_token(
            ecr.get("region").and_then(Value::as_str).unwrap_or(""),
            host,
        )
    } else {
        None
    }
}

/// `{"name":"FASTVERK_TOKEN_…","aliases":["GITLAB_TOKEN"]}` — first non-empty of
/// `name` then each alias wins.
fn resolve_env(env: &Value) -> Option<String> {
    let name = env.get("name").and_then(Value::as_str)?;
    let aliases = env
        .get("aliases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    std::iter::once(name)
        .chain(aliases)
        .filter(|n| !n.is_empty())
        .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
}

/// `{"path":"/run/secrets/tok","field":"TOKEN"}` — trimmed file contents, or a
/// `KEY=VALUE` field when `field` is set.
fn resolve_file(file: &Value) -> Option<String> {
    let path = file.get("path").and_then(Value::as_str)?;
    let field = file.get("field").and_then(Value::as_str).unwrap_or("");
    let raw = std::fs::read_to_string(path).ok()?;
    let val = if field.is_empty() {
        raw.trim().to_string()
    } else {
        raw.lines().find_map(|l| {
            let (k, v) = l.trim().split_once('=')?;
            (k.trim() == field).then(|| v.trim().trim_matches('"').to_string())
        })?
    };
    (!val.is_empty()).then_some(val)
}

/// AWS-ECR authorization: a compiled-in source that mints (and briefly caches)
/// the registry Basic-auth token for a private ECR host.
mod ecr {
    use std::time::Duration;

    /// Re-mint after ~10h; ECR tokens are valid 12h, and a build is far shorter,
    /// so one mint covers a whole build and repeated Bazel fetches read the cache.
    const TTL: Duration = Duration::from_secs(10 * 3600);

    /// The ECR registry Basic-auth token for `region` (empty → `us-east-1`).
    ///
    /// `GetAuthorizationToken` returns a token already equal to
    /// `base64("AWS:<password>")`, so the arm emits it verbatim after its
    /// `"Basic "` prefix. We shell the `aws` CLI rather than link the AWS SDK +
    /// a tokio runtime — the binary stays sync and dependency-light, and the
    /// build pod's IRSA role supplies the creds. The command is FIXED (only the
    /// region is config-supplied), so this is not config-injected execution.
    /// Cached in the temp dir so a build's many fetches don't each hit STS/ECR.
    #[must_use]
    pub fn authorization_token(region: &str, host: &str) -> Option<String> {
        // The docker config FIRST: it is already there and it is free. The build
        // runner's entrypoint runs `crane auth login` before bazel, which writes
        // auths["<registry>"].auth = base64("AWS:<password>") — byte-for-byte what
        // GetAuthorizationToken returns, so the arm emits it verbatim.
        //
        // This is not an optimisation, it is the fix. Shelling awscli costs a
        // PyInstaller cold start + STS AssumeRoleWithWebIdentity + GetAuthorizationToken,
        // which does not fit bazel's credential-helper window: bazel killed the helper
        // ("process timed out"), the fetch fell back to anonymous, ECR answered 401, and
        // EVERY private-ECR base pull died fleet-wide. Worse, the timeout hit before the
        // cache below could ever be written, so every call re-paid and re-died.
        if let Some(tok) = docker_config_auth(host) {
            return Some(tok);
        }
        let region = if region.is_empty() {
            "us-east-1"
        } else {
            region
        };
        let cache = std::env::temp_dir().join(format!("fastverk-ecr-{region}.token"));
        if let Some(tok) = fresh_cache(&cache) {
            return Some(tok);
        }
        let out = std::process::Command::new("aws")
            .args([
                "ecr",
                "get-authorization-token",
                "--region",
                region,
                "--query",
                "authorizationData[0].authorizationToken",
                "--output",
                "text",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let tok = String::from_utf8(out.stdout).ok()?.trim().to_string();
        if tok.is_empty() {
            return None;
        }
        let _ = std::fs::write(&cache, &tok);
        Some(tok)
    }

    /// `auths["<host>"].auth` from the docker config ($DOCKER_CONFIG/config.json,
    /// else ~/.docker/config.json) — what `crane auth login` / `docker login` write.
    /// For ECR that value IS base64("AWS:<password>"), i.e. exactly the shape
    /// GetAuthorizationToken returns, so callers need no re-encoding.
    ///
    /// Best-effort like everything else here: absent/unreadable/malformed = None, and
    /// the caller falls through to minting one.
    fn docker_config_auth(host: &str) -> Option<String> {
        if host.is_empty() {
            return None;
        }
        let path = match std::env::var("DOCKER_CONFIG") {
            Ok(d) if !d.is_empty() => std::path::PathBuf::from(d).join("config.json"),
            // Same home resolution paths::user_bazelrc() already uses.
            _ => directories::BaseDirs::new()?
                .home_dir()
                .join(".docker")
                .join("config.json"),
        };
        let raw = std::fs::read_to_string(path).ok()?;
        let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let tok = doc
            .get("auths")?
            .get(host)?
            .get("auth")?
            .as_str()?
            .trim()
            .to_string();
        (!tok.is_empty()).then_some(tok)
    }

    /// The cached token if it exists and is younger than [`TTL`].
    fn fresh_cache(path: &std::path::Path) -> Option<String> {
        let age = std::fs::metadata(path)
            .ok()?
            .modified()
            .ok()?
            .elapsed()
            .ok()?;
        if age >= TTL {
            return None;
        }
        let tok = std::fs::read_to_string(path).ok()?;
        (!tok.trim().is_empty()).then(|| tok.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    /// The ECR arm must take the token the entrypoint ALREADY wrote to the docker
    /// config, not shell awscli for a fresh one. This is load-bearing, not a
    /// micro-optimisation: minting costs an awscli cold start + STS + ECR, which
    /// overruns bazel's credential-helper window — the helper gets killed
    /// ("process timed out"), the fetch goes anonymous, ECR says 401, and every
    /// private-ECR base pull dies. `DOCKER_CONFIG` is honored so the test never
    /// touches $HOME.
    #[test]
    fn ecr_arm_prefers_the_docker_config_over_minting() {
        let dir = std::env::temp_dir().join(format!("fvk-dockercfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let host = "042825952740.dkr.ecr.us-east-1.amazonaws.com";
        // what `crane auth login` writes: base64("AWS:<password>")
        let want = "QVdTOnBhc3N3b3Jk";
        std::fs::write(
            dir.join("config.json"),
            format!(r#"{{"auths":{{"{host}":{{"auth":"{want}"}}}}}}"#),
        )
        .unwrap();
        // a second config that knows a DIFFERENT registry host
        let dir2 = std::env::temp_dir().join(format!("fvk-dockercfg-x-{}", std::process::id()));
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(
            dir2.join("config.json"),
            r#"{"auths":{"999999999999.dkr.ecr.us-east-1.amazonaws.com":{"auth":"QVdTOm90aGVy"}}}"#,
        )
        .unwrap();

        std::env::set_var("DOCKER_CONFIG", &dir);
        // PATH is emptied: if the arm shells awscli at all, it CANNOT succeed — so a
        // pass here proves the docker-config path was taken, not merely that a token
        // came back from somewhere.
        let saved_path = std::env::var("PATH").unwrap_or_default();
        let saved_path2 = saved_path.clone();
        std::env::set_var("PATH", "");

        let cfg = format!(
            r#"{{"arms":[{{"hostPatterns":["*.dkr.ecr.us-east-1.amazonaws.com"],
                 "valuePrefix":"Basic ","secret":{{"awsEcr":{{"region":"us-east-1"}}}}}}]}}"#
        );
        let got = resolve_in(&cfg, host);

        std::env::set_var("PATH", saved_path);
        std::env::remove_var("DOCKER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);

        let got = got.expect("ecr arm must resolve from the docker config");
        assert_eq!(got.value, format!("Basic {want}"));

        // ...and a host with NO entry must not borrow another host's token. Asserted in
        // the same test on purpose: DOCKER_CONFIG/PATH are process-global, so two tests
        // touching them race under the default parallel harness.
        std::env::set_var("DOCKER_CONFIG", &dir2);
        std::env::set_var("PATH", "");
        let other = resolve_in(&cfg, host);
        std::env::set_var("PATH", &saved_path2);
        std::env::remove_var("DOCKER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir2);
        assert!(other.is_none(), "must not reuse a different host's auth");
    }

    use super::resolve_in;

    /// A gitlab arm whose env var name is unique per test (parallel tests must
    /// not share a mutable env var — mirrors the secretstore tests).
    fn gitlab_cfg(var: &str) -> String {
        format!(
            r#"{{ "arms": [
              {{ "hostPatterns": ["gitlab.savvifi.com", "*.gitlab.savvifi.com"],
                 "header": "Authorization", "valuePrefix": "Bearer ",
                 "secret": {{ "env": {{ "name": "{var}" }} }} }}
            ] }}"#
        )
    }

    #[test]
    fn env_arm_matches_and_prefixes() {
        let var = "CREDTEST_GL_MATCH";
        let cfg = gitlab_cfg(var);
        std::env::set_var(var, "glpat-xyz");
        let c = resolve_in(&cfg, "gitlab.savvifi.com").expect("arm match");
        assert_eq!(c.header, "Authorization");
        assert_eq!(c.value, "Bearer glpat-xyz");
        // wildcard arm too
        assert!(resolve_in(&cfg, "registry.gitlab.savvifi.com").is_some());
        std::env::remove_var(var);
    }

    #[test]
    fn arm_with_unavailable_secret_is_a_miss() {
        // The env isn't set → the arm can't resolve → None (caller falls through).
        let var = "CREDTEST_GL_UNSET";
        std::env::remove_var(var);
        assert!(resolve_in(&gitlab_cfg(var), "gitlab.savvifi.com").is_none());
    }

    #[test]
    fn unmatched_host_and_malformed_are_none() {
        let cfg = gitlab_cfg("CREDTEST_GL_NONE");
        assert!(resolve_in(&cfg, "github.com").is_none());
        assert!(resolve_in("not json", "gitlab.savvifi.com").is_none());
        assert!(resolve_in(r#"{"arms":[]}"#, "gitlab.savvifi.com").is_none());
    }

    #[test]
    fn ecr_cache_read_path() {
        // The fresh-cache path returns a pre-written token without shelling out.
        // Unique region so the cache file can't collide with a real ECR cache or
        // another test.
        let region = "test-region-1";
        let cache = std::env::temp_dir().join(format!("fastverk-ecr-{region}.token"));
        std::fs::write(&cache, "QVdTOnBhc3N3b3Jk").unwrap(); // base64("AWS:password")
        let cfg = format!(
            r#"{{ "arms": [
              {{ "hostPatterns": ["*.dkr.ecr.{region}.amazonaws.com"],
                 "valuePrefix": "Basic ",
                 "secret": {{ "awsEcr": {{ "region": "{region}" }} }} }}
            ] }}"#
        );
        let c = resolve_in(&cfg, &format!("1234.dkr.ecr.{region}.amazonaws.com")).expect("ecr arm");
        assert_eq!(c.value, "Basic QVdTOnBhc3N3b3Jk");
        let _ = std::fs::remove_file(&cache);
    }
}
