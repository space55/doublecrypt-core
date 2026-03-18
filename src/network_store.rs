//! Network-backed block store that connects to a `doublecrypt-server` over mTLS.
//!
//! Uses the 4-byte little-endian length-prefixed protobuf protocol defined in
//! `proto/blockstore.proto`.  The connection is synchronous (matching the
//! [`BlockStore`] trait) but supports:
//!
//! * **Request pipelining** — [`read_blocks`](BlockStore::read_blocks) and
//!   [`write_blocks`](BlockStore::write_blocks) send a full batch of requests
//!   before reading any responses, eliminating per-block round-trip latency.
//! * **Automatic reconnection** — a single retry on I/O failure with a fresh
//!   TLS handshake.
//! * **Configurable timeouts** — connect, read, and write deadlines.
//!
//! # Quick start
//!
//! ```no_run
//! use std::path::Path;
//! use doublecrypt_core::network_store::NetworkBlockStore;
//! use doublecrypt_core::block_store::BlockStore;
//!
//! let store = NetworkBlockStore::connect(
//!     "127.0.0.1:9100",
//!     "localhost",
//!     Path::new("certs/client.pem"),
//!     Path::new("certs/client-key.pem"),
//!     Path::new("certs/ca.pem"),
//! ).expect("connect to server");
//!
//! let data = store.read_block(0).expect("read block 0");
//! ```
//!
//! # Builder
//!
//! ```no_run
//! use std::time::Duration;
//! use doublecrypt_core::network_store::{NetworkBlockStore, NetworkBlockStoreConfig};
//! use doublecrypt_core::block_store::BlockStore;
//!
//! let store = NetworkBlockStore::from_config(
//!     NetworkBlockStoreConfig::new("10.0.0.5:9100", "block-server")
//!         .client_cert("certs/client.pem")
//!         .client_key("certs/client-key.pem")
//!         .ca_cert("certs/ca.pem")
//!         .connect_timeout(Duration::from_secs(5))
//!         .io_timeout(Duration::from_secs(60)),
//! ).expect("connect to server");
//! ```

use std::io::{BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::block_store::BlockStore;
use crate::error::{FsError, FsResult};
use crate::proto;

/// Maximum number of requests to pipeline before reading responses.
///
/// Keeps TCP buffer usage bounded and avoids deadlocks when the kernel
/// send/receive buffers are smaller than the total pipelined payload.
const PIPELINE_BATCH: usize = 64;

// ── Configuration ───────────────────────────────────────────

/// Connection parameters for a [`NetworkBlockStore`].
pub struct NetworkBlockStoreConfig {
    addr: String,
    server_name: String,
    client_cert: PathBuf,
    client_key: PathBuf,
    ca_cert: PathBuf,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl NetworkBlockStoreConfig {
    /// Create a config targeting `addr` (`"host:port"`) with the given TLS
    /// server name (SNI).  Timeouts default to 10 s (connect) and 30 s (I/O).
    pub fn new(addr: impl Into<String>, server_name: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            server_name: server_name.into(),
            client_cert: PathBuf::new(),
            client_key: PathBuf::new(),
            ca_cert: PathBuf::new(),
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        }
    }

    pub fn client_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.client_cert = path.into();
        self
    }

    pub fn client_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.client_key = path.into();
        self
    }

    pub fn ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert = path.into();
        self
    }

    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    pub fn io_timeout(mut self, d: Duration) -> Self {
        self.io_timeout = d;
        self
    }
}

// ── Store ───────────────────────────────────────────────────

/// A [`BlockStore`] backed by a remote `doublecrypt-server` reached over mTLS.
///
/// On construction the client performs a TLS handshake and issues a `GetInfo`
/// RPC to learn the block size and total block count.  The connection is
/// stored and reused; if it breaks, one automatic reconnect is attempted.
pub struct NetworkBlockStore {
    config: NetworkBlockStoreConfig,
    tls_config: Arc<ClientConfig>,
    stream: Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>,
    block_size: usize,
    total_blocks: u64,
    next_request_id: AtomicU64,
}

impl NetworkBlockStore {
    /// Connect to a `doublecrypt-server` using mutual TLS (convenience wrapper
    /// around [`from_config`](Self::from_config)).
    pub fn connect(
        addr: &str,
        server_name: &str,
        client_cert: &Path,
        client_key: &Path,
        ca_cert: &Path,
    ) -> FsResult<Self> {
        Self::from_config(
            NetworkBlockStoreConfig::new(addr, server_name)
                .client_cert(client_cert)
                .client_key(client_key)
                .ca_cert(ca_cert),
        )
    }

    /// Connect using a [`NetworkBlockStoreConfig`].
    pub fn from_config(config: NetworkBlockStoreConfig) -> FsResult<Self> {
        let tls_config =
            build_client_tls_config(&config.client_cert, &config.client_key, &config.ca_cert)?;

        // Establish the initial connection.
        let mut stream = establish_connection(&config, &tls_config)?;

        // Issue GetInfo to learn block geometry.
        let req = proto::Request {
            request_id: 1,
            command: Some(proto::request::Command::GetInfo(proto::GetInfoRequest {})),
        };
        send_message(&mut stream, &req)?;
        let resp = recv_message(&mut stream)?;

        match resp.result {
            Some(proto::response::Result::GetInfo(info)) => Ok(Self {
                config,
                tls_config,
                stream: Mutex::new(Some(stream)),
                block_size: info.block_size as usize,
                total_blocks: info.total_blocks,
                next_request_id: AtomicU64::new(2),
            }),
            Some(proto::response::Result::Error(e)) => Err(FsError::Internal(format!(
                "server error on GetInfo: {}",
                e.message
            ))),
            _ => Err(FsError::Internal("unexpected response to GetInfo".into())),
        }
    }

    /// Allocate a monotonically increasing request ID.
    fn next_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Establish a fresh TLS connection using stored config.
    fn reconnect(&self) -> FsResult<StreamOwned<ClientConnection, TcpStream>> {
        establish_connection(&self.config, &self.tls_config)
    }

    /// Send a single request and receive its response, retrying once on I/O
    /// failure by reconnecting.
    fn roundtrip(&self, req: &proto::Request) -> FsResult<proto::Response> {
        let mut guard = self
            .stream
            .lock()
            .map_err(|e| FsError::Internal(e.to_string()))?;

        // Ensure we have a live connection.
        if guard.is_none() {
            *guard = Some(self.reconnect()?);
        }

        let stream = guard.as_mut().unwrap();
        match send_and_recv(stream, req) {
            Ok(resp) => Ok(resp),
            Err(_) => {
                // Connection may be dead — reconnect and retry once.
                *guard = Some(self.reconnect()?);
                send_and_recv(guard.as_mut().unwrap(), req)
            }
        }
    }

    // ── Pipelined helpers ───────────────────────────────────

    /// Pipeline a batch of read requests on `stream`.
    fn pipeline_reads(
        &self,
        stream: &mut StreamOwned<ClientConnection, TcpStream>,
        block_ids: &[u64],
    ) -> FsResult<Vec<Vec<u8>>> {
        let mut results = Vec::with_capacity(block_ids.len());

        for chunk in block_ids.chunks(PIPELINE_BATCH) {
            // Send all requests in this batch.
            for &block_id in chunk {
                let id = self.next_id();
                send_message(
                    stream,
                    &proto::Request {
                        request_id: id,
                        command: Some(proto::request::Command::ReadBlock(
                            proto::ReadBlockRequest { block_id },
                        )),
                    },
                )?;
            }

            // Read all responses.
            for _ in chunk {
                let resp = recv_message(stream)?;
                match resp.result {
                    Some(proto::response::Result::ReadBlock(r)) => results.push(r.data),
                    Some(proto::response::Result::Error(e)) => {
                        return Err(FsError::Internal(format!("server: {}", e.message)));
                    }
                    _ => return Err(FsError::Internal("unexpected response".into())),
                }
            }
        }

        Ok(results)
    }

    /// Pipeline a batch of write requests on `stream`.
    fn pipeline_writes(
        &self,
        stream: &mut StreamOwned<ClientConnection, TcpStream>,
        blocks: &[(u64, &[u8])],
    ) -> FsResult<()> {
        for chunk in blocks.chunks(PIPELINE_BATCH) {
            for &(block_id, data) in chunk {
                let id = self.next_id();
                send_message(
                    stream,
                    &proto::Request {
                        request_id: id,
                        command: Some(proto::request::Command::WriteBlock(
                            proto::WriteBlockRequest {
                                block_id,
                                data: data.to_vec(),
                            },
                        )),
                    },
                )?;
            }

            for _ in chunk {
                let resp = recv_message(stream)?;
                match resp.result {
                    Some(proto::response::Result::WriteBlock(_)) => {}
                    Some(proto::response::Result::Error(e)) => {
                        return Err(FsError::Internal(format!("server: {}", e.message)));
                    }
                    _ => return Err(FsError::Internal("unexpected response".into())),
                }
            }
        }

        Ok(())
    }

    /// Run a pipelined operation with one reconnect attempt on failure.
    fn with_pipeline<F, T>(&self, op: F) -> FsResult<T>
    where
        F: Fn(&Self, &mut StreamOwned<ClientConnection, TcpStream>) -> FsResult<T>,
    {
        let mut guard = self
            .stream
            .lock()
            .map_err(|e| FsError::Internal(e.to_string()))?;

        if guard.is_none() {
            *guard = Some(self.reconnect()?);
        }

        match op(self, guard.as_mut().unwrap()) {
            Ok(v) => Ok(v),
            Err(_) => {
                *guard = Some(self.reconnect()?);
                op(self, guard.as_mut().unwrap())
            }
        }
    }
}

impl BlockStore for NetworkBlockStore {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    fn read_block(&self, block_id: u64) -> FsResult<Vec<u8>> {
        let id = self.next_id();
        let req = proto::Request {
            request_id: id,
            command: Some(proto::request::Command::ReadBlock(
                proto::ReadBlockRequest { block_id },
            )),
        };
        let resp = self.roundtrip(&req)?;

        match resp.result {
            Some(proto::response::Result::ReadBlock(r)) => Ok(r.data),
            Some(proto::response::Result::Error(e)) => {
                Err(FsError::Internal(format!("server: {}", e.message)))
            }
            _ => Err(FsError::Internal("unexpected response".into())),
        }
    }

    fn write_block(&self, block_id: u64, data: &[u8]) -> FsResult<()> {
        let id = self.next_id();
        let req = proto::Request {
            request_id: id,
            command: Some(proto::request::Command::WriteBlock(
                proto::WriteBlockRequest {
                    block_id,
                    data: data.to_vec(),
                },
            )),
        };
        let resp = self.roundtrip(&req)?;

        match resp.result {
            Some(proto::response::Result::WriteBlock(_)) => Ok(()),
            Some(proto::response::Result::Error(e)) => {
                Err(FsError::Internal(format!("server: {}", e.message)))
            }
            _ => Err(FsError::Internal("unexpected response".into())),
        }
    }

    fn sync(&self) -> FsResult<()> {
        let id = self.next_id();
        let req = proto::Request {
            request_id: id,
            command: Some(proto::request::Command::Sync(proto::SyncRequest {})),
        };
        let resp = self.roundtrip(&req)?;

        match resp.result {
            Some(proto::response::Result::Sync(_)) => Ok(()),
            Some(proto::response::Result::Error(e)) => {
                Err(FsError::Internal(format!("server: {}", e.message)))
            }
            _ => Err(FsError::Internal("unexpected response".into())),
        }
    }

    fn read_blocks(&self, block_ids: &[u64]) -> FsResult<Vec<Vec<u8>>> {
        if block_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.with_pipeline(|s, stream| s.pipeline_reads(stream, block_ids))
    }

    fn write_blocks(&self, blocks: &[(u64, &[u8])]) -> FsResult<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        self.with_pipeline(|s, stream| s.pipeline_writes(stream, blocks))
    }
}

// ── Wire helpers ────────────────────────────────────────────

fn send_message<W: Write>(w: &mut W, msg: &proto::Request) -> FsResult<()> {
    let payload = msg.encode_to_vec();
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())
        .map_err(|e| FsError::Internal(format!("write length prefix: {e}")))?;
    w.write_all(&payload)
        .map_err(|e| FsError::Internal(format!("write payload: {e}")))?;
    w.flush()
        .map_err(|e| FsError::Internal(format!("flush: {e}")))?;
    Ok(())
}

fn recv_message<R: Read>(r: &mut R) -> FsResult<proto::Response> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .map_err(|e| FsError::Internal(format!("read length prefix: {e}")))?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        return Err(FsError::Internal(format!(
            "response too large: {len} bytes"
        )));
    }

    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|e| FsError::Internal(format!("read payload: {e}")))?;

    proto::Response::decode(&*buf).map_err(|e| FsError::Internal(format!("decode response: {e}")))
}

fn send_and_recv(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    req: &proto::Request,
) -> FsResult<proto::Response> {
    send_message(stream, req)?;
    recv_message(stream)
}

// ── Connection establishment ────────────────────────────────

fn establish_connection(
    config: &NetworkBlockStoreConfig,
    tls_config: &Arc<ClientConfig>,
) -> FsResult<StreamOwned<ClientConnection, TcpStream>> {
    let addr = config
        .addr
        .to_socket_addrs()
        .map_err(|e| FsError::Internal(format!("resolve {}: {e}", config.addr)))?
        .next()
        .ok_or_else(|| FsError::Internal(format!("no addresses for {}", config.addr)))?;

    let tcp = TcpStream::connect_timeout(&addr, config.connect_timeout)
        .map_err(|e| FsError::Internal(format!("connect to {}: {e}", config.addr)))?;

    tcp.set_read_timeout(Some(config.io_timeout))
        .map_err(|e| FsError::Internal(format!("set read timeout: {e}")))?;
    tcp.set_write_timeout(Some(config.io_timeout))
        .map_err(|e| FsError::Internal(format!("set write timeout: {e}")))?;

    let sni = ServerName::try_from(config.server_name.clone())
        .map_err(|e| FsError::Internal(format!("invalid SNI '{}': {e}", config.server_name)))?;

    let tls_conn = ClientConnection::new(Arc::clone(tls_config), sni)
        .map_err(|e| FsError::Internal(format!("TLS connection: {e}")))?;

    Ok(StreamOwned::new(tls_conn, tcp))
}

// ── TLS configuration ───────────────────────────────────────

fn build_client_tls_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> FsResult<Arc<ClientConfig>> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| FsError::Internal(format!("read client cert {}: {e}", cert_path.display())))?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(&*cert_pem))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| FsError::Internal(format!("parse client certs: {e}")))?;

    let key_pem = std::fs::read(key_path)
        .map_err(|e| FsError::Internal(format!("read client key {}: {e}", key_path.display())))?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(&*key_pem))
        .map_err(|e| FsError::Internal(format!("parse client key: {e}")))?
        .ok_or_else(|| FsError::Internal("no private key found in PEM file".into()))?;

    let ca_pem = std::fs::read(ca_path)
        .map_err(|e| FsError::Internal(format!("read CA cert {}: {e}", ca_path.display())))?;
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(&*ca_pem))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| FsError::Internal(format!("parse CA certs: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| FsError::Internal(format!("add CA cert: {e}")))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| FsError::Internal(format!("build TLS client config: {e}")))?;

    Ok(Arc::new(config))
}
