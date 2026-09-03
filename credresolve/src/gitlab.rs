//! GitLab registry-capable token helpers.
//!
//! `fv connect gitlab` runs an OAuth device flow and (historically) stored
//! the resulting OAuth *access token*. That token authenticates the GitLab
//! REST API but is rejected with **HTTP 401** by GitLab's package registry
//! (npm/maven/etc.), which only accepts a Personal Access Token (PAT),
//! deploy token, or CI job token carrying `read_package_registry` — or the
//! broader `read_api`/`api` — scope. So a connection holding only an OAuth
//! token authenticates `…/api/v4/projects/…` but NOT
//! `…/api/v4/projects/…/packages/npm/…`, and every Bazel fetch of a GitLab
//! npm/maven artifact 401s.
//!
//! The fix: after the OAuth flow succeeds, mint a registry-capable PAT via
//! `POST /api/v4/user/personal_access_tokens` (GitLab >= 16.1) using the
//! OAuth token as the bearer, and store THAT PAT as the connection's secret.
//! `read_api` covers package-registry reads, so the helper then returns a
//! credential that works for both the API and the registry.
//!
//! Division of labor: `credresolve` owns the *shapes* and the *pure* helpers
//! — the endpoint URL, the request body, the response parse, and the
//! registry-401 detection — so they're unit-testable with no network. `fvkit`
//! owns the HTTP call itself (it already carries the OAuth/network stack),
//! keeping this crate dependency-light on the cred-helper hot path. The
//! `connect`/`--refresh` flow in fvkit is therefore:
//!
//! 1. obtain an `api`-scoped OAuth token (device flow);
//! 2. `POST` [`mint_pat_endpoint`] with header `Authorization: Bearer <oauth>`
//!    and body [`mint_pat_request_json`];
//! 3. parse the reply with [`parse_mint_pat_response`];
//! 4. store `response.token` (the PAT) as the connection's keychain secret —
//!    replacing the OAuth token (`--refresh` does exactly this for an existing
//!    connection);
//! 5. if minting is unavailable (older GitLab, or the OAuth token lacks
//!    `api`), fall back to prompting the user to paste a PAT/deploy token with
//!    `read_api`/`read_package_registry` and store that instead.

use crate::proto::{MintPatRequest, MintPatResponse};

/// Scope we grant the minted PAT. `read_api` is the least privilege that
/// still covers package-registry reads (it implies `read_package_registry`)
/// as well as ordinary API reads, so one connection authenticates both
/// surfaces without any write capability.
pub const MINT_SCOPE: &str = "read_api";

/// Stable PAT name for a host, so a re-mint is recognizable (and revocable)
/// in the user's GitLab token list. E.g. `fastverk-gitlab.savvifi.com`.
#[must_use]
pub fn pat_name(host: &str) -> String {
    format!("fastverk-{host}")
}

/// The PAT-creation endpoint for a GitLab instance. GitLab >= 16.1.
#[must_use]
pub fn mint_pat_endpoint(host: &str) -> String {
    format!("https://{host}/api/v4/user/personal_access_tokens")
}

/// Build the [`MintPatRequest`] for `host`, expiring `days` out (the caller
/// passes the resolved RFC-3339 date; see [`expiry_date`]).
#[must_use]
pub fn mint_pat_request(host: &str, expires_at: impl Into<String>) -> MintPatRequest {
    MintPatRequest {
        name: pat_name(host),
        scopes: vec![MINT_SCOPE.to_string()],
        expires_at: expires_at.into(),
    }
}

/// The JSON body GitLab expects for `POST .../personal_access_tokens`.
/// Hand-built (no serde dep — credresolve is prost-only; the shape is
/// trivial and the rest of the crate hand-builds/parses JSON likewise).
#[must_use]
pub fn mint_pat_request_json(req: &MintPatRequest) -> String {
    let scopes: Vec<String> = req
        .scopes
        .iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect();
    format!(
        "{{\"name\":\"{}\",\"scopes\":[{}],\"expires_at\":\"{}\"}}",
        json_escape(&req.name),
        scopes.join(","),
        json_escape(&req.expires_at),
    )
}

/// Parse the relevant fields out of GitLab's PAT-creation reply. Dependency-
/// free scanner — we only need `token`, `id`, `name`, `expires_at`, `scopes`,
/// and the body is small and well-formed. Returns `None` when there's no
/// `token` (e.g. an error reply), so the caller can fall back to a paste.
#[must_use]
pub fn parse_mint_pat_response(body: &str) -> Option<MintPatResponse> {
    let token = json_string_field(body, "token")?;
    Some(MintPatResponse {
        token,
        id: json_int_field(body, "id").unwrap_or_default(),
        name: json_string_field(body, "name").unwrap_or_default(),
        expires_at: json_string_field(body, "expires_at").unwrap_or_default(),
        scopes: json_string_array_field(body, "scopes").unwrap_or_default(),
    })
}

/// An RFC-3339 *date* (`YYYY-MM-DD`) `days` days after `now_unix` (seconds
/// since the Unix epoch). Pure (no clock dep) so it's testable; the caller
/// passes `SystemTime::now()` seconds. Used for the ~1-year PAT expiry.
#[must_use]
pub fn expiry_date(now_unix: i64, days: i64) -> String {
    let (y, m, d) = civil_from_days(now_unix.div_euclid(86_400) + days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Whether a request URI targets a GitLab package registry path, where an
/// OAuth-only credential 401s. Used to surface a precise "re-mint" hint when
/// a `/packages/` fetch fails auth. Matches the GitLab registry layouts
/// (`/packages/`, `/-/packages/`, the npm/maven/pypi/conan registry roots).
#[must_use]
pub fn is_package_registry_uri(uri: &str) -> bool {
    let path = path_of(uri);
    path.contains("/packages/")
        || path.contains("/-/packages/")
        || path.contains("/packages/npm/")
        || path.contains("/packages/maven/")
        || path.contains("/packages/pypi/")
        || path.contains("/packages/conan/")
}

/// The one-line, copy-pasteable hint we surface when a GitLab registry fetch
/// is about to use an OAuth-only token. `id` is the connection id (e.g.
/// `gitlab` or `gitlab.savvifi.com`).
#[must_use]
pub fn refresh_hint(id: &str) -> String {
    format!(
        "fastverk: this GitLab connection's stored token is OAuth-only, which \
         the package registry rejects (HTTP 401). Re-mint a registry-capable \
         token with: fv connect {id} --refresh"
    )
}

/// Heuristic: does this token look like a registry-capable GitLab token
/// (Personal Access Token, deploy token, or CI job token) rather than an
/// OAuth access token? GitLab PATs are prefixed `glpat-`, deploy tokens
/// `gldt-`, CI job tokens `glcbt-`/`glptt-`, and OAuth access tokens carry
/// no such prefix (a bare 64-char secret, or `gloas-` on newer instances).
/// Used only to decide whether to *proactively warn* on a `/packages/` fetch;
/// it never blocks the fetch. Conservative: unknown shapes are treated as
/// registry-capable so we don't cry wolf.
#[must_use]
pub fn looks_registry_capable(token: &str) -> bool {
    const REGISTRY_PREFIXES: [&str; 5] = ["glpat-", "gldt-", "glcbt-", "glptt-", "glrt-"];
    const OAUTH_PREFIXES: [&str; 1] = ["gloas-"];
    if REGISTRY_PREFIXES.iter().any(|p| token.starts_with(p)) {
        return true;
    }
    if OAUTH_PREFIXES.iter().any(|p| token.starts_with(p)) {
        return false;
    }
    // A bare 64-hex secret with no prefix is the classic OAuth access-token
    // shape; anything else of unknown shape we assume is fine.
    !(token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()))
}

// ─── small dependency-free helpers ─────────────────────────────────────

/// Path component of a URI (everything after the authority, including the
/// leading `/`), or `""`.
fn path_of(uri: &str) -> &str {
    let after_scheme = match uri.find("://") {
        Some(i) => &uri[i + 3..],
        None => uri,
    };
    match after_scheme.find('/') {
        Some(i) => {
            let p = &after_scheme[i..];
            let end = p.find(['?', '#']).unwrap_or(p.len());
            &p[..end]
        }
        None => "",
    }
}

/// JSON-escape a string value (mirrors the cred-helper's escaper).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Extract a JSON string field `"<key>":"<value>"` (honoring backslash
/// escapes in the value). `None` when the key is absent or non-string.
fn json_string_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(rel) = body[from..].find(&needle) {
        let at = from + rel;
        let after = &body[at + needle.len()..];
        let colon = after.find(':')?;
        let rest = after[colon + 1..].trim_start();
        if let Some(stripped) = rest.strip_prefix('"') {
            return Some(unescape_json_until_quote(stripped));
        }
        // Key matched but value isn't a string here (e.g. `"id":123`); keep
        // scanning for another occurrence.
        from = at + needle.len();
    }
    None
}

/// Extract a JSON integer field `"<key>":<int>`.
fn json_int_field(body: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let at = body.find(&needle)?;
    let after = &body[at + needle.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Extract a JSON array-of-strings field `"<key>":["a","b"]`.
fn json_string_array_field(body: &str, key: &str) -> Option<Vec<String>> {
    let needle = format!("\"{key}\"");
    let at = body.find(&needle)?;
    let after = &body[at + needle.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let open = rest.strip_prefix('[')?;
    let close = open.find(']')?;
    let inner = &open[..close];
    let mut out = Vec::new();
    let mut chars = inner.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '"' {
            let s = unescape_json_until_quote(&inner[i + 1..]);
            // Advance the cursor past this element's closing quote.
            let consumed = json_string_len(&inner[i + 1..]);
            for _ in 0..consumed {
                chars.next();
            }
            out.push(s);
        }
    }
    Some(out)
}

/// Read a JSON string body (the part after the opening quote) up to the
/// terminating unescaped quote, applying the common escapes.
fn unescape_json_until_quote(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some(other) => out.push(other),
                None => break,
            },
            _ => out.push(c),
        }
    }
    out
}

/// Number of chars consumed (including the closing quote) by the JSON string
/// whose body starts at `s` — used to advance past an array element.
fn json_string_len(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        n += 1;
        match c {
            '"' => return n,
            // Skip the escaped char so an escaped quote doesn't end the string.
            '\\' if chars.next().is_some() => n += 1,
            _ => {}
        }
    }
    n
}

/// Convert a count of days since the Unix epoch to a (year, month, day)
/// proleptic-Gregorian date. Howard Hinnant's `civil_from_days` algorithm —
/// exact, no external date crate (credresolve stays dependency-light).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::{
        civil_from_days, expiry_date, is_package_registry_uri, looks_registry_capable,
        mint_pat_endpoint, mint_pat_request, mint_pat_request_json, parse_mint_pat_response,
        pat_name, refresh_hint, MINT_SCOPE,
    };

    #[test]
    fn endpoint_and_name() {
        assert_eq!(
            mint_pat_endpoint("gitlab.savvifi.com"),
            "https://gitlab.savvifi.com/api/v4/user/personal_access_tokens"
        );
        assert_eq!(pat_name("gitlab.savvifi.com"), "fastverk-gitlab.savvifi.com");
    }

    #[test]
    fn request_body_is_well_formed() {
        let req = mint_pat_request("gitlab.savvifi.com", "2027-06-15");
        assert_eq!(req.scopes, vec![MINT_SCOPE.to_string()]);
        assert_eq!(
            mint_pat_request_json(&req),
            r#"{"name":"fastverk-gitlab.savvifi.com","scopes":["read_api"],"expires_at":"2027-06-15"}"#
        );
    }

    #[test]
    fn parses_mint_response() {
        // Shape of a real GitLab >= 16.1 reply (token redacted-style value).
        let body = r#"{"id":123,"name":"fastverk-gitlab.savvifi.com","revoked":false,
            "scopes":["read_api"],"token":"glpat-EXAMPLEEXAMPLE","expires_at":"2027-06-15"}"#;
        let r = parse_mint_pat_response(body).expect("token present");
        assert_eq!(r.token, "glpat-EXAMPLEEXAMPLE");
        assert_eq!(r.id, 123);
        assert_eq!(r.name, "fastverk-gitlab.savvifi.com");
        assert_eq!(r.expires_at, "2027-06-15");
        assert_eq!(r.scopes, vec!["read_api".to_string()]);
        // An error reply (no token) -> None, so the caller can fall back.
        assert!(parse_mint_pat_response(r#"{"message":"401 Unauthorized"}"#).is_none());
    }

    #[test]
    fn detects_registry_uris() {
        assert!(is_package_registry_uri(
            "https://gitlab.savvifi.com/api/v4/projects/121/packages/npm/@aion/auth-model/-/@aion/auth-model-0.1.4.tgz"
        ));
        assert!(is_package_registry_uri(
            "https://gitlab.savvifi.com/api/v4/projects/121/packages/maven/com/x/1.0/x-1.0.jar"
        ));
        // A plain API call is NOT a registry path.
        assert!(!is_package_registry_uri(
            "https://gitlab.savvifi.com/api/v4/projects/121"
        ));
        // A repo clone is not a registry path.
        assert!(!is_package_registry_uri(
            "https://gitlab.savvifi.com/group/repo.git/info/refs"
        ));
    }

    #[test]
    fn hint_names_the_connection_and_refresh() {
        let h = refresh_hint("gitlab.savvifi.com");
        assert!(h.contains("fv connect gitlab.savvifi.com --refresh"));
        assert!(h.contains("401"));
    }

    #[test]
    fn token_shape_heuristic() {
        // PAT / deploy / CI-job / runner tokens are registry-capable.
        assert!(looks_registry_capable("glpat-EXAMPLEEXAMPLEEXAMPLE"));
        assert!(looks_registry_capable("gldt-EXAMPLEEXAMPLE"));
        assert!(looks_registry_capable("glcbt-1-EXAMPLE"));
        // A bare 64-hex secret is the classic OAuth access-token shape.
        let oauth64 = "a".repeat(64);
        assert!(!looks_registry_capable(&oauth64));
        // Newer instances prefix OAuth tokens `gloas-`.
        assert!(!looks_registry_capable("gloas-EXAMPLEEXAMPLE"));
        // Unknown shapes are assumed fine (don't cry wolf).
        assert!(looks_registry_capable("some-pasted-deploy-token"));
    }

    #[test]
    fn expiry_date_is_correct() {
        // 2026-06-15 is 20619 days after the epoch (1970-01-01).
        // 20619 * 86400 = 1781481600.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_619), (2026, 6, 15));
        // ~1 year (365 days) out from a fixed instant.
        assert_eq!(expiry_date(1_781_481_600, 365), "2027-06-15");
        // Leap-year boundary sanity: epoch + 365 days = 1971-01-01.
        assert_eq!(expiry_date(0, 365), "1971-01-01");
    }
}
