//! `qagent` — an MCP server a node operator runs beside `qclient`.
//!
//! It speaks MCP over HTTP. Every request must carry a named API key
//! (`Authorization: Bearer` or `X-Api-Key`). The log records that key's name.
//! A quote is printed on this host with its confirmation id. The MCP client
//! is told only that a quote is waiting, and it cannot submit. `qagent confirm`
//! on this machine submits, and only when the fee is still inside the
//! configured slippage and automatic cap. The process that accepts MCP
//! connections does not open the keystore; a helper process does, then exits.

pub mod auth;
pub mod config;
pub mod control;
pub mod guide;
pub mod http;
pub mod mcp;
pub mod ops;
pub mod slippage;
pub mod worker;

pub use config::Settings;
pub use http::serve;
