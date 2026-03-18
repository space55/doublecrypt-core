//! Protobuf types for the doublecrypt block-store protocol.
//!
//! These are hand-written prost structs matching `proto/blockstore.proto`.
//! They are wire-compatible with the length-prefixed protobuf protocol used
//! by `doublecrypt-server` and can be imported directly by both the client
//! ([`NetworkBlockStore`](crate::network_store::NetworkBlockStore)) and the
//! server, avoiding any need for `protoc` or `prost-build`.
//!
//! # Usage from `doublecrypt-server`
//!
//! ```toml
//! [dependencies]
//! doublecrypt-core = { version = "0.1", default-features = false }
//! ```
//!
//! ```rust,ignore
//! use doublecrypt_core::proto::{Request, Response, request, response};
//! ```

// ── Requests ────────────────────────────────────────────────

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(oneof = "request::Command", tags = "2, 3, 4, 5")]
    pub command: ::core::option::Option<request::Command>,
}

pub mod request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Command {
        #[prost(message, tag = "2")]
        ReadBlock(super::ReadBlockRequest),
        #[prost(message, tag = "3")]
        WriteBlock(super::WriteBlockRequest),
        #[prost(message, tag = "4")]
        Sync(super::SyncRequest),
        #[prost(message, tag = "5")]
        GetInfo(super::GetInfoRequest),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadBlockRequest {
    #[prost(uint64, tag = "1")]
    pub block_id: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WriteBlockRequest {
    #[prost(uint64, tag = "1")]
    pub block_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncRequest {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetInfoRequest {}

// ── Responses ───────────────────────────────────────────────

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(oneof = "response::Result", tags = "2, 3, 4, 5, 6")]
    pub result: ::core::option::Option<response::Result>,
}

pub mod response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "2")]
        ReadBlock(super::ReadBlockResponse),
        #[prost(message, tag = "3")]
        WriteBlock(super::WriteBlockResponse),
        #[prost(message, tag = "4")]
        Sync(super::SyncResponse),
        #[prost(message, tag = "5")]
        GetInfo(super::GetInfoResponse),
        #[prost(message, tag = "6")]
        Error(super::ErrorResponse),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadBlockResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WriteBlockResponse {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncResponse {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetInfoResponse {
    #[prost(uint32, tag = "1")]
    pub block_size: u32,
    #[prost(uint64, tag = "2")]
    pub total_blocks: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorResponse {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}
