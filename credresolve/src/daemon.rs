//! Client for the fastverk daemon (`fvd`) — the Keychain-prompt-once path.
//!
//! Why this exists: on macOS the login Keychain re-prompts for a password
//! whenever the *reading binary* is not in the stored item's access-control
//! list (ACL). The cred-helper is rebuilt and re-downloaded routinely (each
//! release is a fresh, differently-signed binary), so it is never in the
//! item's ACL and macOS re-prompts on *every* Bazel fetch — a terrible
//! experience.
//!
//! The fix is to route Keychain reads through the long-lived `fvd` daemon.
//! `fvd` is launched once (e.g. by the menu-bar app / a LaunchAgent), unlocks
//! the item once on first read (one prompt for the whole login session), and
//! thereafter answers cred-helper read requests over the Unix-domain socket
//! at `$FASTVERK_SOCKET` without touching the Keychain UI again. The
//! cred-helper, when the daemon is reachable, never opens a Keychain entry
//! itself, so its short-lived, ever-changing binary identity is irrelevant.
//!
//! Persistent trust for `fvd` itself: `fvd` should add ITS OWN binary to the
//! stored item's `SecAccess` ACL using a **designated requirement** keyed on
//! the signing identity (a code-signing-identity-based trusted application),
//! not the on-disk path or cdhash. A re-signed or upgraded `fvd` from the same
//! identity then stays trusted, so the one prompt survives upgrades. fvkit
//! owns that write (it owns `connect` and the Keychain item's creation); this
//! crate owns the read protocol.
//!
//! Wire framing: a 4-byte big-endian length prefix, then a prost-encoded
//! [`DaemonRequest`]; the reply is the same framing around a
//! [`DaemonResponse`]. One request/response per connection. Everything here
//! is best-effort: any socket/decoding/daemon error is treated as "daemon
//! unavailable" so [`crate::credstore`] falls back to a direct read and the
//! build never fails because `fvd` is down.

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use prost::Message;

#[cfg(unix)]
use crate::paths;
#[cfg(unix)]
use crate::proto::{
    daemon_request, daemon_response, DaemonRequest, DaemonResponse, GetSecretRequest,
};

/// Connect timeout / read timeout for the daemon round-trip. The cred-helper
/// is on Bazel's per-host hot path, so we never block long: if `fvd` doesn't
/// answer promptly we fall back to the direct Keychain read.
#[cfg(unix)]
const DAEMON_TIMEOUT: Duration = Duration::from_millis(750);

/// Ask `fvd` to read a keychain item by `(service, account)`.
///
/// Returns:
/// * `Some(Ok(Some(secret)))` — daemon answered, item found;
/// * `Some(Ok(None))` — daemon answered, item absent;
/// * `Some(Err(_))` — daemon answered with a structured error;
/// * `None` — daemon unreachable / unusable, caller should fall back.
///
/// The `None` arm is the important one: it cleanly separates "the daemon told
/// us the item isn't there" (authoritative) from "we couldn't reach the
/// daemon" (fall back to a direct read).
#[cfg(unix)]
#[must_use]
pub fn get_secret(service: &str, account: &str) -> Option<anyhow::Result<Option<String>>> {
    let sock = paths::socket_path().ok()?;
    if !sock.exists() {
        return None;
    }
    let req = DaemonRequest {
        request: Some(daemon_request::Request::GetSecret(GetSecretRequest {
            service: service.to_string(),
            account: account.to_string(),
        })),
    };
    match round_trip(&sock, &req) {
        Ok(DaemonResponse {
            response: Some(daemon_response::Response::GetSecret(g)),
        }) => Some(Ok(g.found.then_some(g.secret))),
        Ok(DaemonResponse {
            response: Some(daemon_response::Response::Error(e)),
        }) => Some(Err(anyhow::anyhow!("fvd: {}", e.message))),
        // Empty/unknown response, or any transport/decode failure: treat the
        // daemon as unavailable so the caller falls back.
        _ => None,
    }
}

/// Non-unix: there is no Unix socket, so the daemon path is always a miss and
/// the caller reads the Keychain (or its stub) directly.
#[cfg(not(unix))]
#[must_use]
pub fn get_secret(_service: &str, _account: &str) -> Option<anyhow::Result<Option<String>>> {
    None
}

/// Send one framed request and read one framed response.
#[cfg(unix)]
fn round_trip(sock: &std::path::Path, req: &DaemonRequest) -> anyhow::Result<DaemonResponse> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(DAEMON_TIMEOUT))?;
    stream.set_write_timeout(Some(DAEMON_TIMEOUT))?;

    let payload = req.encode_to_vec();
    let len = u32::try_from(payload.len())?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    // Bound the reply so a misbehaving peer can't make us allocate unbounded.
    anyhow::ensure!(resp_len <= 1 << 20, "fvd response too large");
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf)?;
    Ok(DaemonResponse::decode(buf.as_slice())?)
}

/// Encode a [`DaemonRequest`]/[`DaemonResponse`] with the 4-byte length
/// prefix the wire protocol uses. Exposed so an `fvd` implementation (and the
/// round-trip test) frames replies identically without duplicating the format.
#[cfg(unix)]
#[must_use]
pub fn frame<M: Message>(msg: &M) -> Vec<u8> {
    let payload = msg.encode_to_vec();
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

#[cfg(all(test, unix))]
mod tests {
    use super::{frame, get_secret, round_trip};
    use crate::proto::{
        daemon_request, daemon_response, DaemonRequest, DaemonResponse, GetSecretResponse,
    };
    use prost::Message;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    /// A throwaway `fvd` stand-in: accept one connection, read the framed
    /// request, and reply with a framed [`GetSecretResponse`] echoing the
    /// requested account so the test can assert the round-trip end to end.
    fn spawn_stub(path: std::path::PathBuf, found: bool, secret: &'static str) {
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut len = [0u8; 4];
                conn.read_exact(&mut len).unwrap();
                let n = u32::from_be_bytes(len) as usize;
                let mut buf = vec![0u8; n];
                conn.read_exact(&mut buf).unwrap();
                let req = DaemonRequest::decode(buf.as_slice()).unwrap();
                // Confirm we received a get_secret request.
                assert!(matches!(
                    req.request,
                    Some(daemon_request::Request::GetSecret(_))
                ));
                let resp = DaemonResponse {
                    response: Some(daemon_response::Response::GetSecret(GetSecretResponse {
                        found,
                        secret: secret.to_string(),
                    })),
                };
                conn.write_all(&frame(&resp)).unwrap();
                conn.flush().unwrap();
            }
        });
    }

    #[test]
    fn round_trip_via_socket() {
        let dir = std::env::temp_dir().join(format!("fvd-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("fvd.sock");
        let _ = std::fs::remove_file(&sock);
        spawn_stub(sock.clone(), true, "s3cr3t");
        // Give the listener a moment to bind.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let req = DaemonRequest {
            request: Some(daemon_request::Request::GetSecret(
                crate::proto::GetSecretRequest {
                    service: "fastverk.gitlab".into(),
                    account: "pat".into(),
                },
            )),
        };
        let resp = round_trip(&sock, &req).unwrap();
        match resp.response {
            Some(daemon_response::Response::GetSecret(g)) => {
                assert!(g.found);
                assert_eq!(g.secret, "s3cr3t");
            }
            other => panic!("unexpected response: {other:?}"),
        }
        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn missing_socket_falls_back() {
        // Point at a socket that doesn't exist -> None (caller falls back).
        let prev = std::env::var("FASTVERK_SOCKET").ok();
        std::env::set_var(
            "FASTVERK_SOCKET",
            std::env::temp_dir().join("fvd-does-not-exist.sock"),
        );
        assert!(get_secret("fastverk.gitlab", "pat").is_none());
        match prev {
            Some(v) => std::env::set_var("FASTVERK_SOCKET", v),
            None => std::env::remove_var("FASTVERK_SOCKET"),
        }
    }
}
