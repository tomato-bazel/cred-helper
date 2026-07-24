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

fn main() {
    // Lenient on the subcommand: only `get` does anything.
    if std::env::args().nth(1).as_deref() != Some("get") {
        println!("{EMPTY}");
        return;
    }
    let mut body = String::new();
    // Consume stdin fully so Bazel's writer never sees EPIPE.
    let _ = std::io::stdin().read_to_string(&mut body);

    let out = respond(&body);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{out}");
}

fn respond(body: &str) -> String {
    let Some(uri) = credresolve::uri::parse_request_uri(body) else {
        return EMPTY.to_string();
    };
    // The connection registry resolves the header for the request host
    // through the secret backends (keychain locally, canonical env vars in
    // CI). `resolve` falls back to the built-in default registry, so CI with
    // no registry file still authenticates via the env backend. Any miss —
    // unknown host, no stored secret, or an error — degrades to anonymous.
    match credresolve::connections::resolve(&uri) {
        Ok(Some(c)) => headers(&c.header, &c.value, c.expires.as_deref()),
        _ => EMPTY.to_string(),
    }
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
