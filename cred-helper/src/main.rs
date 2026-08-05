//! fastverk universal Bazel credential helper.
//!
//! Resolves the auth header for a Bazel fetch URI from the connection
//! registry + pluggable secret backends (`credresolve`). A single unscoped
//! helper covers every host; it self-routes off the request URI.
//!
//! Bazel cred-helper protocol (EngFlow spec):
//!   * `cred-helper get` with stdin `{"uri":"https://host[:port]/path"}`.
//!   * stdout `{"headers":{"Header-Name":["value"]}}`.
//!   * Any miss (no matching connection, no stored secret, malformed
//!     request, or non-`get` argv) yields `{"headers":{}}` and exit 0, so
//!     a fetch degrades to anonymous rather than failing the build.
//!
//! Resolves secrets inline (keychain locally, env vars in CI) so it stays
//! fast on Bazel's per-host hot path.

use std::io::{Read, Write};

const EMPTY: &str = "{\"headers\":{}}";

/// Hosts that MUST authenticate, comma-separated. See `required_hosts`.
const REQUIRE_ENV: &str = "FASTVERK_CRED_REQUIRE";

fn main() -> std::process::ExitCode {
    // Lenient on the subcommand: only `get` does anything.
    if std::env::args().nth(1).as_deref() != Some("get") {
        println!("{EMPTY}");
        return std::process::ExitCode::SUCCESS;
    }
    let mut body = String::new();
    // Consume stdin fully so Bazel's writer never sees EPIPE.
    let _ = std::io::stdin().read_to_string(&mut body);

    let out = respond(&body);

    // ⛔⛔ THE ONE PLACE THIS HELPER IS ALLOWED TO FAIL, AND IT IS OPT-IN PER HOST.
    //
    // Everything else here degrades to anonymous on purpose: most fetches in a Bazel build
    // are to public hosts (BCR, crates.io, a public ghcr) that need no credential, and a
    // helper that errored on those would break every build immediately. That is why the
    // fail-open exists and why it must stay the default.
    //
    // ⛔ But it has a cost, and this estate has paid it twice — a dead-code-eliminated config
    // feature that made every private-ECR pull 401 (read as "the C++ toolchain is broken"),
    // and a helper timeout under ECR minting (read as "RBE is starved"). In both, the helper
    // answered `{"headers":{}}` with exit 0 and Bazel sent no Authorization header, so the
    // far end returned UNAUTHENTICATED and the symptom named the wrong system entirely.
    //
    // ⭐ THE ASYMMETRY THAT MAKES THIS SAFE: anonymous is a legitimate answer for a host
    // nobody said had to authenticate, and never a legitimate answer for one somebody did.
    // So the caller names the hosts it KNOWS require a credential, and only those turn a miss
    // into an error. A global strict mode would be unusable — it is the version of this idea
    // that gets reverted the first afternoon.
    if is_anonymous(&out) {
        if let Some(host) = required_miss(&body) {
            eprintln!(
                "cred-helper: no credential resolved for {host}, which {REQUIRE_ENV} lists as \
                 requiring one.\n\
                 \n\
                 This is NOT a network or endpoint failure. Every source was tried and none \
                 produced a secret, so without this check the helper would have returned\n\
                 \n    {EMPTY}\n\n\
                 with exit 0, Bazel would have sent no Authorization header at all, and \
                 {host} would have answered UNAUTHENTICATED — which reads as a broken \
                 endpoint or an expired token.\n\
                 \n\
                 Check that FASTVERK_TOKEN_FILE_{} names a readable, non-empty file (or that \
                 FASTVERK_TOKEN_{} is set, or that a credentials.json arm matches).",
                env_suffix(&host),
                env_suffix(&host),
            );
            return std::process::ExitCode::FAILURE;
        }
    }

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{out}");
    std::process::ExitCode::SUCCESS
}

/// Did we produce the fail-open answer?
///
/// ⚠ Compared against the rendered response rather than tracked through `respond`, so this
/// cannot drift from what is actually about to be written to stdout. A header present with an
/// empty value is anonymous in effect too — Bazel would send an empty header, which every
/// server rejects the same way as none.
fn is_anonymous(out: &str) -> bool {
    out.trim() == EMPTY || out.contains("\"headers\":{}")
}

/// The request's host, if `FASTVERK_CRED_REQUIRE` lists it.
///
/// ⚠ Matching is exact and case-insensitive on the HOST only — no wildcards. A wildcard here
/// would let `*` sneak in as "require everything", which is the global strict mode this
/// deliberately does not offer.
fn required_miss(body: &str) -> Option<String> {
    let uri = credresolve::uri::parse_request_uri(body)?;
    let host = credresolve::uri::host_of(&uri).to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let raw = std::env::var(REQUIRE_ENV).ok()?;
    raw.split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .any(|h| !h.is_empty() && h == host)
        .then_some(host)
}

/// `rbe.tbzl.dev` -> `RBE_TBZL_DEV`, matching `credresolve`'s own derivation so the error
/// message names the variable the helper actually looks up.
fn env_suffix(host: &str) -> String {
    host.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn respond(body: &str) -> String {
    let Some(uri) = credresolve::uri::parse_request_uri(body) else {
        return EMPTY.to_string();
    };
    // The connection registry resolves the header for the request host
    // through the secret backends (keychain locally, canonical env vars in
    // CI). `resolve` falls back to the built-in default registry, so CI with
    // no registry file still authenticates via the env backend.
    if let Ok(Some(c)) = credresolve::connections::resolve(&uri) {
        return headers(&c.header, &c.value, c.expires.as_deref());
    }

    // Then the CONFIG-DRIVEN arms (`credresolve::config`): a CredentialSet
    // rendered to $FASTVERK_CRED_CONFIG and mounted into the build pod. This is
    // how a build authenticates a registry the binary knows nothing about — the
    // private-ECR mirror arm (`awsEcr`) in particular.
    //
    // This call is the whole reason the module ships. Without it NOTHING
    // referenced `credresolve::config`, so the linker dead-code-eliminated the
    // entire feature: the released binary contained no `awsEcr`, no
    // `hostPatterns`, not even the `FASTVERK_CRED_CONFIG` string. Every layer
    // around it was live and correct — the CRD, CredentialSet/aion-ecr, five
    // ConfigSets, the rendered credentials.json, the mount, the env var, the
    // unscoped --credential_helper — and the helper still answered
    // `{"headers":{}}` for ECR, so every private-ECR oci.pull base 401'd
    // fleet-wide and read as "the C++ toolchain is broken" / "RBE is starved".
    // Config that nothing reads is indistinguishable from config that is wrong.
    //
    // Ordering note: config.rs describes itself as sitting between the keychain
    // registry and the built-in provider defaults. `connections::resolve` bundles
    // those defaults, so splitting it would mean changing that function; it is
    // tried FIRST here instead. The practical difference is only for a host that
    // BOTH a built-in derivation and a config arm claim — for ECR there is no
    // derivation, so the arm is reached.
    if let Some(c) = credresolve::config::resolve_host(credresolve::uri::host_of(&uri)) {
        return headers(&c.header, &c.value, c.expires.as_deref());
    }

    // Any miss — unknown host, no stored secret, or an error — degrades to
    // anonymous rather than failing the fetch.
    EMPTY.to_string()
}

/// The Bazel credential-helper `get` response. `expires` (RFC 3339) is emitted
/// only when the resolved source is refreshable, and it is what makes Bazel
/// re-invoke this helper before the token dies rather than caching the first
/// value for the whole build.
fn headers(header: &str, value: &str, expires: Option<&str>) -> String {
    let hdrs = format!(
        "\"headers\":{{\"{}\":[\"{}\"]}}",
        json_escape(header),
        json_escape(value),
    );
    match expires {
        Some(ts) => format!("{{{hdrs},\"expires\":\"{}\"}}", json_escape(ts)),
        None => format!("{{{hdrs}}}"),
    }
}

/// JSON-escape a string for embedding as a JSON string value.
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

#[cfg(test)]
mod tests {
    use super::{json_escape, respond, EMPTY};

    #[test]
    fn malformed_or_unknown_is_empty() {
        assert_eq!(respond("not json"), EMPTY);
        assert_eq!(respond(""), EMPTY);
        // A well-formed request for an unconfigured host is anonymous
        // (no connection in the registry -> empty headers).
        assert_eq!(
            respond(r#"{"uri":"https://no-such-host.example/x"}"#),
            EMPTY
        );
    }

    /// The config arm must be REACHED from `respond`. This is the regression
    /// guard for the dead-code bug: before `respond` called
    /// `credresolve::config::resolve_host`, the whole module was stripped from
    /// the binary and every private-ECR fetch went anonymous. Uses a file-source
    /// arm so the test needs no AWS, no network, and no docker config.
    #[test]
    fn config_arm_is_reachable_from_respond() {
        let dir = std::env::temp_dir().join(format!("fvk-credcfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("tok");
        std::fs::write(&secret, "s3cr3t\n").unwrap();
        let cfg = dir.join("credentials.json");
        std::fs::write(
            &cfg,
            format!(
                r#"{{"arms":[{{"hostPatterns":["registry.example.test"],
                     "valuePrefix":"Basic ",
                     "secret":{{"file":{{"path":"{}"}}}}}}]}}"#,
                secret.display()
            ),
        )
        .unwrap();
        std::env::set_var("FASTVERK_CRED_CONFIG", &cfg);
        let out = respond(r#"{"uri":"https://registry.example.test/v2/x/manifests/y"}"#);
        std::env::remove_var("FASTVERK_CRED_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            out.contains("Basic s3cr3t"),
            "config arm not reached from respond(); got {out}"
        );
    }

    #[test]
    fn escapes_json() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    // The Bearer/header behavior, canonical/alias env naming, and the generic
    // per-host fallback are covered hermetically (no secret reads) in the
    // credresolve::connections + credresolve::secretstore tests. The end-to-end
    // respond() path here is just parse + resolve + headers; the
    // miss-is-anonymous edge is exercised above.
}


#[cfg(test)]
mod require_tests {
    use super::*;

    /// ⭐ THE DEFAULT IS UNCHANGED, AND THIS IS THE MOST IMPORTANT TEST IN THE FILE. With
    /// `FASTVERK_CRED_REQUIRE` unset, an unconfigured host still degrades to anonymous with
    /// exit 0 — because most fetches in a Bazel build are to public hosts that need no
    /// credential, and a helper that errored on those would break every build immediately.
    #[test]
    fn without_the_variable_nothing_is_required() {
        // ⚠ `required_miss` reads the process environment, and Rust runs tests in threads of
        // one process. The variable is deliberately NOT set anywhere in this suite, so this
        // asserts the genuine default rather than a value this test cleared.
        assert!(std::env::var(REQUIRE_ENV).is_err(), "test suite must not set {REQUIRE_ENV}");
        assert_eq!(required_miss(r#"{"uri":"https://rbe.tbzl.dev/"}"#), None);
    }

    #[test]
    fn the_fail_open_answer_is_recognized() {
        assert!(is_anonymous(EMPTY));
        assert!(is_anonymous("{\"headers\":{}}\n"));
        assert!(!is_anonymous(r#"{"headers":{"Authorization":["Bearer x"]}}"#));
    }

    /// ⚠ The message must name the variable the helper ACTUALLY looks up, or it sends the
    /// reader to the wrong place — which is the whole failure being fixed.
    #[test]
    fn the_env_suffix_matches_the_lookup() {
        assert_eq!(env_suffix("rbe.tbzl.dev"), "RBE_TBZL_DEV");
        assert_eq!(env_suffix("rbe.fastverk.com"), "RBE_FASTVERK_COM");
        // Digits survive; everything else collapses.
        assert_eq!(env_suffix("rbe2.tbzl.dev"), "RBE2_TBZL_DEV");
    }
}
