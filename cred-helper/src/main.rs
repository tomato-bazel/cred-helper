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
/// cannot drift from what is actually about to be written to stdout.
///
/// ⭐ "Anonymous" includes a header present with an EMPTY value, not just an absent header
/// map. Bazel would send `Authorization:` with nothing after it, and a server rejects that
/// exactly as it rejects no header at all — so treating it as a credential would make the
/// require check pass while the fetch still 401s, which is the precise failure this whole
/// mechanism exists to stop. No source can currently produce one (every backend filters empty
/// secrets), so this is defensive: it keeps the check true if one ever learns how.
fn is_anonymous(out: &str) -> bool {
    out.trim() == EMPTY || out.contains("\"headers\":{}") || out.contains("[\"\"]")
}

/// The request's host, if `FASTVERK_CRED_REQUIRE` lists it.
fn required_miss(body: &str) -> Option<String> {
    let uri = credresolve::uri::parse_request_uri(body)?;
    let host = credresolve::uri::host_of(&uri).to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let raw = std::env::var(REQUIRE_ENV).ok()?;
    host_is_required(&raw, &host).then_some(host)
}

/// Whether `require_list` (the raw `FASTVERK_CRED_REQUIRE` value) names `host`.
///
/// ⚠ Matching is exact and case-insensitive on the HOST only — no wildcards. A wildcard here
/// would let `*` sneak in as "require everything", which is the global strict mode this
/// deliberately does not offer.
///
/// ⭐ Split out from [`required_miss`] so the MATCHING RULE is testable without touching the
/// process environment. That is not tidiness: `FASTVERK_CRED_REQUIRE` has one fixed name, Rust
/// runs tests as threads of one process, and the previous shape left the rule reachable only
/// through a `set_var` no test was willing to do. Verified by mutation — inverting `h == host`
/// to `h != host`, i.e. "require every host EXCEPT this one", passed the entire suite.
/// `host` is expected already lowercased and non-empty.
fn host_is_required(require_list: &str, host: &str) -> bool {
    require_list
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .any(|h| !h.is_empty() && h == host)
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
        // Surface any non-secret diagnostic (e.g. a GitLab package-registry
        // fetch about to use an OAuth-only token, which the registry 401s)
        // on stderr — never on stdout, which carries the protocol reply.
        if let Some(w) = &c.warning {
            eprintln!("{w}");
        }
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
        // ⚠ Asserted through the PURE rule, not through the process environment. The
        // original form of this test asserted `std::env::var(REQUIRE_ENV).is_err()` and
        // relied on no test in the suite ever setting it — which is what kept the positive
        // path uncovered, and would now race with
        // `required_miss_reads_the_env_and_normalizes_the_host` below. An absent variable
        // and an empty list reach `host_is_required` identically: nothing is required.
        assert!(!host_is_required("", "rbe.tbzl.dev"));
        assert!(!host_is_required("", "github.com"));
        // The env-unset path itself is asserted in the single env-mutating test below,
        // which owns that variable for the whole suite.
    }

    #[test]
    fn the_fail_open_answer_is_recognized() {
        assert!(is_anonymous(EMPTY));
        assert!(is_anonymous("{\"headers\":{}}\n"));
        assert!(!is_anonymous(r#"{"headers":{"Authorization":["Bearer x"]}}"#));
        // ⭐ A present-but-empty header is anonymous IN EFFECT: Bazel sends
        // `Authorization:` with nothing after it and the server rejects it exactly as it
        // rejects no header. Counting it as a credential would let the require check pass
        // on a request that still 401s.
        assert!(is_anonymous(r#"{"headers":{"Authorization":[""]}}"#));
    }

    // ─── The matching rule ───────────────────────────────────────────────────────
    //
    // ⛔⛔ THESE ARE THE TESTS WHOSE ABSENCE MADE THE FEATURE INERT. Before them, the
    // positive path of `FASTVERK_CRED_REQUIRE` was reachable only through a `set_var` no
    // test performed, so the matching rule was never executed under test at all. Proven by
    // mutation: inverting `h == host` to `h != host` — "require every host EXCEPT this
    // one", the exact opposite of the documented behavior — passed the whole suite.
    //
    // ⭐ They call `host_is_required` rather than `required_miss` on purpose. The rule then
    // needs no process environment, so it can be covered exhaustively without the
    // set_var-in-parallel-threads race that kept it uncovered in the first place.

    /// The listed host is required. This is the positive path — the one that was inert.
    #[test]
    fn a_listed_host_is_required() {
        assert!(host_is_required("rbe.tbzl.dev", "rbe.tbzl.dev"));
        // …and it is found anywhere in the list, not just first.
        assert!(host_is_required("a.example,rbe.tbzl.dev,z.example", "rbe.tbzl.dev"));
        assert!(host_is_required("a.example,rbe.tbzl.dev", "rbe.tbzl.dev"));
    }

    /// ⭐ The mutation guard. An unlisted host must NOT be required — this is the assertion
    /// the inverted implementation fails, and the one that makes the pair above meaningful.
    /// A test that only ever asserts `true` cannot tell a working rule from a reversed one.
    #[test]
    fn an_unlisted_host_is_not_required() {
        assert!(!host_is_required("rbe.tbzl.dev", "github.com"));
        assert!(!host_is_required("a.example,b.example", "rbe.tbzl.dev"));
        assert!(!host_is_required("", "rbe.tbzl.dev"));
        // ⚠ A near-miss must not match: no prefix, suffix, or substring semantics.
        assert!(!host_is_required("rbe.tbzl.dev", "rbe.tbzl.de"));
        assert!(!host_is_required("rbe.tbzl.dev", "notrbe.tbzl.dev"));
        assert!(!host_is_required("tbzl.dev", "rbe.tbzl.dev"));
    }

    /// ⛔ NO WILDCARDS. The README promises `*` cannot sneak in as "require everything",
    /// because a global strict mode is the version of this idea that gets reverted the first
    /// afternoon. That promise was previously untested — a wildcard implementation would
    /// have shipped green.
    #[test]
    fn wildcards_are_not_honored() {
        assert!(!host_is_required("*", "rbe.tbzl.dev"));
        assert!(!host_is_required("*.tbzl.dev", "rbe.tbzl.dev"));
        assert!(!host_is_required("rbe.*", "rbe.tbzl.dev"));
        // A literal "*" entry is inert even beside a real one, which still matches.
        assert!(host_is_required("*,rbe.tbzl.dev", "rbe.tbzl.dev"));
        assert!(!host_is_required("*,other.example", "rbe.tbzl.dev"));
    }

    /// Whitespace and case are normalized on BOTH sides — a hand-edited list with spaces
    /// after the commas, or a host the caller capitalized, must still match.
    #[test]
    fn matching_is_case_insensitive_and_trims() {
        assert!(host_is_required(" rbe.tbzl.dev , other.example ", "rbe.tbzl.dev"));
        assert!(host_is_required("RBE.TBZL.DEV", "rbe.tbzl.dev"));
        assert!(host_is_required("\tRbE.TbZl.DeV\t", "rbe.tbzl.dev"));
        // ⚠ Empty entries from a trailing/doubled comma are skipped, never matched. An
        // empty `host` can't reach here (`required_miss` returns early), but an empty LIST
        // entry must not become a wildcard by accident.
        assert!(!host_is_required(",,", "rbe.tbzl.dev"));
        assert!(host_is_required("rbe.tbzl.dev,,", "rbe.tbzl.dev"));
    }

    /// ⭐ End-to-end through the env var, closing the gap between the rule above and what
    /// `main` actually calls: the port is stripped, the host is lowercased, and a miss on an
    /// unlisted host stays `None`.
    ///
    /// ⚠ Assertions are bundled into ONE test deliberately. `FASTVERK_CRED_REQUIRE` has a
    /// single fixed name (unlike the per-test unique names `credresolve`'s tests use), and
    /// Rust runs tests as threads of one process — so two tests mutating it would race. Same
    /// reasoning, and same shape, as the DOCKER_CONFIG/PATH test in `credresolve::config`.
    /// The variable is restored before returning so the default-behavior test still sees it
    /// unset regardless of thread order.
    #[test]
    fn required_miss_reads_the_env_and_normalizes_the_host() {
        let req = r#"{"uri":"https://RBE.tbzl.dev:8980/v1/x"}"#;

        std::env::set_var(REQUIRE_ENV, "rbe.tbzl.dev");
        // Host is lowercased and the :8980 port is stripped before matching.
        assert_eq!(required_miss(req).as_deref(), Some("rbe.tbzl.dev"));
        // A different host in the same process is still not required.
        assert_eq!(required_miss(r#"{"uri":"https://github.com/a"}"#), None);
        // A malformed body yields None rather than an error.
        assert_eq!(required_miss("not json"), None);

        std::env::remove_var(REQUIRE_ENV);
        assert_eq!(required_miss(req), None);
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
