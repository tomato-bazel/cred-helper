//! `credresolve` — fastverk credential resolution core.
//!
//! The shared, dependency-light closure behind the Bazel credential helper:
//! the connection-registry schema (proto), the read/resolve path, and the
//! pluggable secret backends (keychain / env / file). The standalone
//! `cred-helper` binary is a thin wrapper over [`connections::resolve`]; the
//! fastverk app (`fvkit`) layers `connect`/OAuth on top of this same core, so
//! the registry contract lives in exactly one place.

/// Generated prost bindings for `fastverk.v1`. Messages only — no gRPC; the
/// resolve path never needs tonic, and //proto:prost_toolchain is configured
/// tonic-free so tokio cannot reach the per-fetch helper binary.
///
/// ⚠ This is a RE-EXPORT, not an `include!`. `rust_prost_library` emits a
/// separate crate named after the `proto_library` TARGET — `connection_proto`,
/// with the module path mirroring the proto package — so the generated types
/// live at `connection_proto::fastverk::v1`. Re-exporting them here keeps every
/// existing `crate::proto::{...}` path compiling unchanged, which is why
/// replacing build.rs touched one line rather than every call site.
pub use connection_proto::fastverk::v1 as proto;

pub mod config;
pub mod connections;
pub mod credstore;
pub mod daemon;
pub mod gitlab;
pub mod paths;
pub mod secretstore;
pub mod uri;
