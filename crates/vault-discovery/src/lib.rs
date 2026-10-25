use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vault_identity::ParticipationKey;

const VERSION: u8 = 1;
const MAX_ENDPOINT_BYTES: usize = 256;
const MAX_RECORDS_PER_DISCOVERY: usize = 64;
const MAX_DISCOVERIES: usize = 1024;
pub const MAX_TTL_SECONDS: u64 = 900;
const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error("discovery record is malformed")]
    Malformed,
    #[error("discovery record is expired or exceeds the maximum TTL")]
    InvalidTtl,
    #[error("discovery record signature is invalid")]
    InvalidSignature,
    #[error("discovery table capacity reached")]
    Capacity,
}

#[derive(Debug, Error)]
pub enum RendezvousError {
    #[error("rendezvous I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rendezvous request is malformed")]
    MalformedRequest,
    #[error("rendezvous request body is too large")]
    BodyTooLarge,
    #[error("rendezvous clock is invalid")]
    Clock,
}

#[derive(Debug, Error)]
pub enum RendezvousClientError {
    #[error("rendezvous client I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rendezvous response is malformed")]
    MalformedResponse,
    #[error("rendezvous response is too large")]
    ResponseTooLarge,
    #[error("rendezvous returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("rendezvous payload is invalid: {0}")]
    Discovery(#[from] DiscoveryError),
}

#[derive(Debug, Clone)]
pub struct RendezvousConfig {
    pub max_connections: usize,
    pub requests_per_ip_per_minute: usize,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub read_timeout: Duration,
}

impl Default for RendezvousConfig {
    fn default() -> Self { Self { max_connections: 256, requests_per_ip_per_minute: 60, max_header_bytes: MAX_HTTP_HEADER_BYTES, max_body_bytes: MAX_HTTP_BODY_BYTES, read_timeout: Duration::from_secs(5) } }
}

#[derive(Debug, Clone)]
pub struct RendezvousClientConfig {
    pub max_response_bytes: usize,
    pub timeout: Duration,
}

impl Default for RendezvousClientConfig {
    fn default() -> Self { Self { max_response_bytes: 64 * 1024, timeout: Duration::from_secs(5) } }
}

pub fn derive_discovery_id(swarm_id: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, swarm_id);
    let mut discovery_id = [0u8; 32];
    hkdf.expand(b"vault/v1/discovery", &mut discovery_id).expect("fixed HKDF output length");
    discovery_id
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRecord {
    pub discovery_id: [u8; 32],
    pub peer_id: [u8; 32],
    pub participation_pubkey: [u8; 32],
    pub relay_endpoint: String,
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl DiscoveryRecord {
    pub fn signed(
        discovery_id: [u8; 32],
        relay_endpoint: impl Into<String>,
        expires_at: u64,
        participation_key: &ParticipationKey,
    ) -> Result<Self, DiscoveryError> {
        let relay_endpoint = relay_endpoint.into();
        validate_endpoint(&relay_endpoint)?;
        let participation_pubkey = participation_key.public_key();
        let peer_id = peer_id_from_public(&participation_pubkey);
        let mut record = Self { discovery_id, peer_id, participation_pubkey, relay_endpoint, expires_at, signature: [0; 64] };
        record.signature = participation_key.sign(&record.signing_bytes());
        Ok(record)
    }

    pub fn verify(&self) -> Result<(), DiscoveryError> {
        validate_endpoint(&self.relay_endpoint)?;
        if self.peer_id != peer_id_from_public(&self.participation_pubkey) {
            return Err(DiscoveryError::Malformed);
        }
        let key = VerifyingKey::from_bytes(&self.participation_pubkey).map_err(|_| DiscoveryError::Malformed)?;
        key.verify(&self.signing_bytes(), &Signature::from_bytes(&self.signature)).map_err(|_| DiscoveryError::InvalidSignature)
    }

    pub fn validate_ttl(&self, now: u64) -> Result<(), DiscoveryError> {
        if self.expires_at <= now || self.expires_at - now > MAX_TTL_SECONDS { Err(DiscoveryError::InvalidTtl) } else { Ok(()) }
    }

    pub fn encode(&self) -> Vec<u8> {
        let endpoint = self.relay_endpoint.as_bytes();
        let mut bytes = Vec::with_capacity(1 + 32 + 32 + 32 + 2 + endpoint.len() + 8 + 64);
        bytes.extend_from_slice(&self.signing_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        let mut cursor = Cursor::new(bytes);
        if read_u8(&mut cursor)? != VERSION { return Err(DiscoveryError::Malformed); }
        let discovery_id = read_array::<32>(&mut cursor)?;
        let peer_id = read_array::<32>(&mut cursor)?;
        let participation_pubkey = read_array::<32>(&mut cursor)?;
        let endpoint_len = read_u16(&mut cursor)? as usize;
        if endpoint_len == 0 || endpoint_len > MAX_ENDPOINT_BYTES { return Err(DiscoveryError::Malformed); }
        let mut endpoint_bytes = vec![0; endpoint_len];
        cursor.read_exact(&mut endpoint_bytes).map_err(|_| DiscoveryError::Malformed)?;
        let relay_endpoint = String::from_utf8(endpoint_bytes).map_err(|_| DiscoveryError::Malformed)?;
        let expires_at = read_u64(&mut cursor)?;
        let signature = read_array::<64>(&mut cursor)?;
        if cursor.position() != bytes.len() as u64 { return Err(DiscoveryError::Malformed); }
        Ok(Self { discovery_id, peer_id, participation_pubkey, relay_endpoint, expires_at, signature })
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let endpoint = self.relay_endpoint.as_bytes();
        let mut bytes = Vec::with_capacity(1 + 32 + 32 + 32 + 2 + endpoint.len() + 8);
        bytes.push(VERSION);
        bytes.extend_from_slice(&self.discovery_id);
        bytes.extend_from_slice(&self.peer_id);
        bytes.extend_from_slice(&self.participation_pubkey);
        bytes.extend_from_slice(&(endpoint.len() as u16).to_le_bytes());
        bytes.extend_from_slice(endpoint);
        bytes.extend_from_slice(&self.expires_at.to_le_bytes());
        bytes
    }
}

pub struct RendezvousTable {
    records: HashMap<[u8; 32], Vec<DiscoveryRecord>>,
}

impl Default for RendezvousTable {
    fn default() -> Self { Self::new() }
}

impl RendezvousTable {
    pub fn new() -> Self { Self { records: HashMap::new() } }

    pub fn register(&mut self, record: DiscoveryRecord, now: u64) -> Result<(), DiscoveryError> {
        record.verify()?;
        record.validate_ttl(now)?;
        self.purge(now);
        if !self.records.contains_key(&record.discovery_id) && self.records.len() >= MAX_DISCOVERIES {
            return Err(DiscoveryError::Capacity);
        }
        let records = self.records.entry(record.discovery_id).or_default();
        if let Some(current) = records.iter_mut().find(|current| current.peer_id == record.peer_id) {
            *current = record;
            return Ok(());
        }
        if records.len() >= MAX_RECORDS_PER_DISCOVERY { return Err(DiscoveryError::Capacity); }
        records.push(record);
        Ok(())
    }

    pub fn query(&mut self, discovery_id: [u8; 32], now: u64) -> Vec<DiscoveryRecord> {
        self.purge(now);
        self.records.get(&discovery_id).cloned().unwrap_or_default()
    }

    fn purge(&mut self, now: u64) {
        self.records.retain(|_, records| {
            records.retain(|record| record.expires_at > now);
            !records.is_empty()
        });
    }
}

pub fn encode_records(records: &[DiscoveryRecord]) -> Result<Vec<u8>, DiscoveryError> {
    if records.len() > MAX_RECORDS_PER_DISCOVERY { return Err(DiscoveryError::Capacity); }
    let mut out = Vec::new();
    put_u16(&mut out, records.len());
    for record in records {
        let bytes = record.encode();
        put_u32(&mut out, bytes.len());
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

pub fn decode_records(bytes: &[u8]) -> Result<Vec<DiscoveryRecord>, DiscoveryError> {
    let mut cursor = Cursor::new(bytes);
    let count = read_u16(&mut cursor)? as usize;
    if count > MAX_RECORDS_PER_DISCOVERY { return Err(DiscoveryError::Malformed); }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let length = read_u32(&mut cursor)? as usize;
        if length == 0 || length > 1024 { return Err(DiscoveryError::Malformed); }
        let mut encoded = vec![0u8; length];
        cursor.read_exact(&mut encoded).map_err(|_| DiscoveryError::Malformed)?;
        let record = DiscoveryRecord::decode(&encoded)?;
        record.verify()?;
        records.push(record);
    }
    if cursor.position() != bytes.len() as u64 { return Err(DiscoveryError::Malformed); }
    Ok(records)
}

pub struct RendezvousServer {
    config: RendezvousConfig,
}

impl RendezvousServer {
    pub fn new(config: RendezvousConfig) -> Self { Self { config } }

    pub fn serve(self, listener: TcpListener) -> Result<(), RendezvousError> {
        let table = Arc::new(Mutex::new(RendezvousTable::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let rate_limits = Arc::new(Mutex::new(HashMap::<IpAddr, (Instant, usize)>::new()));
        for incoming in listener.incoming() {
            let stream = incoming?;
            let ip = stream.peer_addr().map(|address| address.ip()).map_err(RendezvousError::Io)?;
            if !allow_request(ip, self.config.requests_per_ip_per_minute, &rate_limits) {
                write_response(&stream, 429, b"rate limited", "text/plain")?;
                continue;
            }
            if !reserve_connection(&active, self.config.max_connections) {
                write_response(&stream, 503, b"busy", "text/plain")?;
                continue;
            }
            let config = self.config.clone();
            let table = Arc::clone(&table);
            let active = Arc::clone(&active);
            thread::spawn(move || {
                let _ = handle_request(stream, &config, &table);
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
        Ok(())
    }
}

fn allow_request(ip: IpAddr, limit: usize, state: &Arc<Mutex<HashMap<IpAddr, (Instant, usize)>>>) -> bool {
    let Ok(mut state) = state.lock() else { return false; };
    let now = Instant::now();
    state.retain(|_, (started, _)| now.duration_since(*started) < Duration::from_secs(60));
    let entry = state.entry(ip).or_insert((now, 0));
    if entry.1 >= limit { return false; }
    entry.1 += 1;
    true
}

fn reserve_connection(active: &AtomicUsize, limit: usize) -> bool {
    loop {
        let current = active.load(Ordering::Acquire);
        if current >= limit { return false; }
        if active.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire).is_ok() { return true; }
    }
}

fn handle_request(mut stream: TcpStream, config: &RendezvousConfig, table: &Arc<Mutex<RendezvousTable>>) -> Result<(), RendezvousError> {
    stream.set_read_timeout(Some(config.read_timeout))?;
    stream.set_write_timeout(Some(config.read_timeout))?;
    let (method, path, body) = read_request(&mut stream, config)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| RendezvousError::Clock)?.as_secs();
    match (method.as_str(), path.as_str()) {
        ("POST", "/v1/register") => {
            let record = DiscoveryRecord::decode(&body).map_err(|_| RendezvousError::MalformedRequest)?;
            let result = table.lock().map_err(|_| RendezvousError::MalformedRequest)?.register(record, now);
            match result {
                Ok(()) => write_response(&stream, 204, &[], "text/plain")?,
                Err(DiscoveryError::Capacity) => write_response(&stream, 429, b"capacity", "text/plain")?,
                Err(DiscoveryError::InvalidTtl) => write_response(&stream, 422, b"invalid ttl", "text/plain")?,
                Err(_) => write_response(&stream, 400, b"invalid record", "text/plain")?,
            }
        }
        ("GET", path) if path.starts_with("/v1/query/") => {
            let discovery_id = decode_hex_32(&path[10..]).ok_or(RendezvousError::MalformedRequest)?;
            let records = table.lock().map_err(|_| RendezvousError::MalformedRequest)?.query(discovery_id, now);
            let body = encode_records(&records).map_err(|_| RendezvousError::MalformedRequest)?;
            write_response(&stream, 200, &body, "application/octet-stream")?;
        }
        _ => write_response(&stream, 404, b"not found", "text/plain")?,
    }
    Ok(())
}

fn read_request(stream: &mut TcpStream, config: &RendezvousConfig) -> Result<(String, String, Vec<u8>), RendezvousError> {
    let header_limit = config.max_header_bytes.min(MAX_HTTP_HEADER_BYTES);
    let body_limit = config.max_body_bytes.min(MAX_HTTP_BODY_BYTES);
    let mut bytes = Vec::with_capacity(header_limit);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 { return Err(RendezvousError::MalformedRequest); }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > header_limit { return Err(RendezvousError::BodyTooLarge); }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") { break end + 4; }
    };
    let header = std::str::from_utf8(&bytes[..header_end]).map_err(|_| RendezvousError::MalformedRequest)?;
    let mut lines = header.split("\r\n");
    let request = lines.next().ok_or(RendezvousError::MalformedRequest)?;
    let mut parts = request.split_whitespace();
    let method = parts.next().ok_or(RendezvousError::MalformedRequest)?.to_owned();
    let path = parts.next().ok_or(RendezvousError::MalformedRequest)?.to_owned();
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() { return Err(RendezvousError::MalformedRequest); }
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() { continue; }
        let (name, value) = line.split_once(':').ok_or(RendezvousError::MalformedRequest)?;
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().map_err(|_| RendezvousError::MalformedRequest)?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(RendezvousError::MalformedRequest);
        }
    }
    if content_length > body_limit { return Err(RendezvousError::BodyTooLarge); }
    let mut body = bytes[header_end..].to_vec();
    body.resize(content_length, 0);
    if bytes.len() - header_end < content_length { stream.read_exact(&mut body[bytes.len() - header_end..])?; }
    Ok((method, path, body))
}

fn write_response(stream: &TcpStream, status: u16, body: &[u8], content_type: &str) -> Result<(), RendezvousError> {
    let reason = match status { 200 => "OK", 204 => "No Content", 400 => "Bad Request", 404 => "Not Found", 422 => "Unprocessable Entity", 429 => "Too Many Requests", 503 => "Service Unavailable", _ => "Error" };
    let response = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len());
    let mut stream = stream.try_clone()?;
    stream.write_all(response.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

pub struct RendezvousClient {
    config: RendezvousClientConfig,
}

impl RendezvousClient {
    pub fn new(config: RendezvousClientConfig) -> Self { Self { config } }

    pub fn register<A: ToSocketAddrs>(&self, address: A, record: &DiscoveryRecord) -> Result<(), RendezvousClientError> {
        record.verify()?;
        send_http_request(address, &self.config, "POST", "/v1/register", &record.encode()).map(|_| ())
    }

    pub fn query<A: ToSocketAddrs>(&self, address: A, discovery_id: [u8; 32]) -> Result<Vec<DiscoveryRecord>, RendezvousClientError> {
        let path = format!("/v1/query/{}", hex32(&discovery_id));
        decode_records(&send_http_request(address, &self.config, "GET", &path, &[])?)
            .map_err(RendezvousClientError::from)
    }
}

fn send_http_request<A: ToSocketAddrs>(address: A, config: &RendezvousClientConfig, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>, RendezvousClientError> {
    if body.len() > MAX_HTTP_BODY_BYTES { return Err(RendezvousClientError::ResponseTooLarge); }
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(config.timeout))?;
    stream.set_write_timeout(Some(config.timeout))?;
    let request = format!("{method} {path} HTTP/1.1\r\nHost: rendezvous\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    read_http_response(&mut stream, config.max_response_bytes.min(64 * 1024))
}

fn read_http_response(stream: &mut TcpStream, max_response_bytes: usize) -> Result<Vec<u8>, RendezvousClientError> {
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 { return Err(RendezvousClientError::MalformedResponse); }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_HTTP_HEADER_BYTES { return Err(RendezvousClientError::ResponseTooLarge); }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") { break end + 4; }
    };
    let header = std::str::from_utf8(&bytes[..header_end]).map_err(|_| RendezvousClientError::MalformedResponse)?;
    let mut lines = header.split("\r\n");
    let status_line = lines.next().ok_or(RendezvousClientError::MalformedResponse)?;
    let mut status_parts = status_line.split_whitespace();
    if status_parts.next() != Some("HTTP/1.1") { return Err(RendezvousClientError::MalformedResponse); }
    let status = status_parts.next().ok_or(RendezvousClientError::MalformedResponse)?.parse::<u16>().map_err(|_| RendezvousClientError::MalformedResponse)?;
    let mut content_length = None;
    for line in lines {
        if line.is_empty() { continue; }
        let (name, value) = line.split_once(':').ok_or(RendezvousClientError::MalformedResponse)?;
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() { return Err(RendezvousClientError::MalformedResponse); }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| RendezvousClientError::MalformedResponse)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(RendezvousClientError::MalformedResponse);
        }
    }
    let content_length = content_length.ok_or(RendezvousClientError::MalformedResponse)?;
    if content_length > max_response_bytes { return Err(RendezvousClientError::ResponseTooLarge); }
    let mut body = bytes[header_end..].to_vec();
    if body.len() > content_length { body.truncate(content_length); }
    if body.len() < content_length {
        let current = body.len();
        body.resize(content_length, 0);
        stream.read_exact(&mut body[current..])?;
    }
    if !(200..300).contains(&status) { return Err(RendezvousClientError::HttpStatus(status)); }
    Ok(body)
}

fn peer_id_from_public(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"vault/v1/participation-peer-id");
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

fn validate_endpoint(endpoint: &str) -> Result<(), DiscoveryError> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES || endpoint.bytes().any(|byte| byte == 0 || byte.is_ascii_control()) { Err(DiscoveryError::Malformed) } else { Ok(()) }
}

fn put_u16(out: &mut Vec<u8>, value: usize) { out.extend_from_slice(&(value as u16).to_le_bytes()); }
fn put_u32(out: &mut Vec<u8>, value: usize) { out.extend_from_slice(&(value as u32).to_le_bytes()); }
fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, DiscoveryError> { let mut bytes = [0; 1]; cursor.read_exact(&mut bytes).map_err(|_| DiscoveryError::Malformed)?; Ok(bytes[0]) }
fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, DiscoveryError> { let mut bytes = [0; 2]; cursor.read_exact(&mut bytes).map_err(|_| DiscoveryError::Malformed)?; Ok(u16::from_le_bytes(bytes)) }
fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, DiscoveryError> { let mut bytes = [0; 4]; cursor.read_exact(&mut bytes).map_err(|_| DiscoveryError::Malformed)?; Ok(u32::from_le_bytes(bytes)) }
fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, DiscoveryError> { let mut bytes = [0; 8]; cursor.read_exact(&mut bytes).map_err(|_| DiscoveryError::Malformed)?; Ok(u64::from_le_bytes(bytes)) }
fn read_array<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], DiscoveryError> { let mut bytes = [0; N]; cursor.read_exact(&mut bytes).map_err(|_| DiscoveryError::Malformed)?; Ok(bytes) }
fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 { return None; }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}
fn hex32(bytes: &[u8; 32]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_id_is_stable_and_swarm_scoped() {
        let first = [1; 32];
        assert_eq!(derive_discovery_id(&first), derive_discovery_id(&first));
        assert_ne!(derive_discovery_id(&first), derive_discovery_id(&[2; 32]));
    }

    #[test]
    fn signed_records_round_trip_and_expire() {
        let discovery_id = derive_discovery_id(&[7; 32]);
        let key = ParticipationKey::generate();
        let record = DiscoveryRecord::signed(discovery_id, "relay.example:443", 110, &key).unwrap();
        let decoded = DiscoveryRecord::decode(&record.encode()).unwrap();
        decoded.verify().unwrap();
        let mut table = RendezvousTable::new();
        table.register(decoded, 100).unwrap();
        assert_eq!(table.query(discovery_id, 109).len(), 1);
        assert!(table.query(discovery_id, 110).is_empty());
    }

    #[test]
    fn table_enforces_ttl_and_capacity() {
        let discovery_id = derive_discovery_id(&[9; 32]);
        let mut table = RendezvousTable::new();
        for _ in 0..MAX_RECORDS_PER_DISCOVERY {
            let key = ParticipationKey::generate();
            table.register(DiscoveryRecord::signed(discovery_id, "relay.example:443", 200, &key).unwrap(), 100).unwrap();
        }
        let key = ParticipationKey::generate();
        assert_eq!(table.register(DiscoveryRecord::signed(discovery_id, "relay.example:443", 200, &key).unwrap(), 100), Err(DiscoveryError::Capacity));
        let key = ParticipationKey::generate();
        assert_eq!(table.register(DiscoveryRecord::signed(discovery_id, "relay.example:443", 1101, &key).unwrap(), 100), Err(DiscoveryError::InvalidTtl));
    }

    #[test]
    fn record_batches_round_trip_with_bounds() {
        let discovery_id = derive_discovery_id(&[3; 32]);
        let key = ParticipationKey::generate();
        let record = DiscoveryRecord::signed(discovery_id, "relay.example:443", 200, &key).unwrap();
        let encoded = encode_records(std::slice::from_ref(&record)).unwrap();
        assert_eq!(decode_records(&encoded).unwrap(), vec![record]);
        assert!(decode_records(&[0xff; 2]).is_err());
    }

    #[test]
    fn connection_reservation_is_bounded() {
        let active = AtomicUsize::new(0);
        assert!(reserve_connection(&active, 1));
        assert!(!reserve_connection(&active, 1));
        active.fetch_sub(1, Ordering::AcqRel);
        assert!(reserve_connection(&active, 1));
    }
}
