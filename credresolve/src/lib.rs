//! `credresolve` — fastverk credential resolution core.
//!
//! The shared, dependency-light closure behind the Bazel credential helper:
//! the connection-registry schema (proto), the read/resolve path, and the
//! pluggable secret backends (keychain / env / file). The standalone
//! `cred-helper` binary is a thin wrapper over [`connections::resolve`]; the
//! fastverk app (`fvkit`) layers `connect`/OAuth on top of this same core, so
//! the registry contract lives in exactly one place.

/// Generated prost bindings for `fastverk.v1` (see `build.rs`). Messages
/// only — no gRPC; the resolve path never needs tonic.
pub mod proto {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
    include!(concat!(env!("OUT_DIR"), "/fastverk.v1.rs"));
}

pub mod config;
pub mod connections;
pub mod credstore;
pub mod paths;
pub mod secretstore;
pub mod uri;
