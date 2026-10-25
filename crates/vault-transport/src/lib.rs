//! Opaque relay transport.
//!
//! The relay only pairs two peers and forwards bounded byte frames. Capability
//! validation and application authorization remain in `vault-protocol`.
//! Transport security is deliberately application-encryption-only: this crate
//! does not terminate TLS and must not be used to send plaintext application data.

use std::{
    collections::HashMap,
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, TcpListener, TcpStream, ToSocketAddrs},
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex, Weak},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAGIC: &[u8; 8] = b"VREL\0\0\0\x01";
const JOIN: u8 = 1;
const ACCEPTED: u8 = 0;
const REJECTED_CAPACITY: u8 = 1;
const REJECTED_DUPLICATE: u8 = 2;
const REJECTED_RATE_LIMIT: u8 = 3;
const REJECTED_SHUTTING_DOWN: u8 = 4;
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024 + 128 * 1024;
pub const RELAY_SECURITY_POLICY: &str = "application-encryption-only";

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Malformed,
    FrameTooLarge,
    HandshakeRejected(u8),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Malformed => formatter.write_str("relay frame is malformed"),
            Self::FrameTooLarge => formatter.write_str("relay frame is too large"),
            Self::HandshakeRejected(code) => write!(formatter, "relay handshake rejected ({code})"),
        }
    }
}

impl std::error::Error for TransportError {}
impl From<io::Error> for TransportError { fn from(error: io::Error) -> Self { Self::Io(error) } }

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub max_circuits: usize,
    pub max_frame_size: usize,
    pub max_circuit_bytes: u64,
    pub max_pending_handshakes: usize,
    pub handshakes_per_ip_per_minute: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_circuits: 1024,
            max_frame_size: MAX_FRAME_SIZE,
            max_circuit_bytes: 64 * 1024 * 1024 * 1024,
            max_pending_handshakes: 1024,
            handshakes_per_ip_per_minute: 60,
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(120),
            shutdown_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayMetricsSnapshot {
    pub accepted_connections: u64,
    pub rejected_connections: u64,
    pub rate_limited_connections: u64,
    pub failed_handshakes: u64,
    pub completed_handshakes: u64,
    pub active_circuits: u64,
    pub closed_circuits: u64,
    pub forwarded_frames: u64,
    pub forwarded_bytes: u64,
}

#[derive(Clone, Default)]
pub struct RelayMetrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    accepted_connections: AtomicU64,
    rejected_connections: AtomicU64,
    rate_limited_connections: AtomicU64,
    failed_handshakes: AtomicU64,
    completed_handshakes: AtomicU64,
    active_circuits: AtomicU64,
    closed_circuits: AtomicU64,
    forwarded_frames: AtomicU64,
    forwarded_bytes: AtomicU64,
}

impl RelayMetrics {
    pub fn snapshot(&self) -> RelayMetricsSnapshot {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        RelayMetricsSnapshot {
            accepted_connections: load(&self.inner.accepted_connections),
            rejected_connections: load(&self.inner.rejected_connections),
            rate_limited_connections: load(&self.inner.rate_limited_connections),
            failed_handshakes: load(&self.inner.failed_handshakes),
            completed_handshakes: load(&self.inner.completed_handshakes),
            active_circuits: load(&self.inner.active_circuits),
            closed_circuits: load(&self.inner.closed_circuits),
            forwarded_frames: load(&self.inner.forwarded_frames),
            forwarded_bytes: load(&self.inner.forwarded_bytes),
        }
    }
}

pub struct RelayClient {
    stream: TcpStream,
    max_frame_size: usize,
}

impl RelayClient {
    pub fn connect<A: ToSocketAddrs>(address: A, circuit_id: [u8; 32], peer_id: [u8; 32], config: &RelayConfig) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(config.handshake_timeout))?;
        stream.set_write_timeout(Some(config.handshake_timeout))?;
        join(&stream, circuit_id, peer_id)?;
        stream.set_read_timeout(Some(config.idle_timeout))?;
        stream.set_write_timeout(Some(config.idle_timeout))?;
        Ok(Self { stream, max_frame_size: config.max_frame_size.min(MAX_FRAME_SIZE) })
    }

    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> { write_frame(&mut self.stream, frame, self.max_frame_size) }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError> { read_frame(&mut self.stream, self.max_frame_size) }

    pub fn shutdown(&self) -> Result<(), TransportError> { self.stream.shutdown(Shutdown::Both).map_err(TransportError::Io) }
}

pub struct RelayServer {
    config: RelayConfig,
    metrics: RelayMetrics,
}

impl RelayServer {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config: RelayConfig { max_frame_size: config.max_frame_size.min(MAX_FRAME_SIZE), ..config },
            metrics: RelayMetrics::default(),
        }
    }

    pub fn metrics(&self) -> RelayMetrics { self.metrics.clone() }

    pub fn start(self, listener: TcpListener) -> RelayServerHandle {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = Arc::clone(&shutdown);
        let join = thread::spawn(move || self.serve_until(listener, shutdown_for_thread));
        RelayServerHandle { shutdown, join: Some(join) }
    }

    pub fn serve(self, listener: TcpListener) -> Result<(), TransportError> {
        self.serve_until(listener, Arc::new(AtomicBool::new(false)))
    }

    pub fn serve_until(self, listener: TcpListener, shutdown: Arc<AtomicBool>) -> Result<(), TransportError> {
        listener.set_nonblocking(true)?;
        let state = Arc::new(Mutex::new(RelayState::new(self.metrics.clone())));
        loop {
            if shutdown.load(Ordering::Acquire) {
                begin_shutdown(&state);
                wait_for_shutdown(&state, self.config.shutdown_timeout);
                return Ok(());
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    self.metrics.inner.accepted_connections.fetch_add(1, Ordering::Relaxed);
                    let ip = stream.peer_addr().map(|address| address.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
                    let stream = Arc::new(Mutex::new(stream));
                    let accepted = reserve_handshake(&state, ip, self.config.handshakes_per_ip_per_minute, self.config.max_pending_handshakes, &stream);
                    if !accepted {
                        self.metrics.inner.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if let Ok(mut guard) = state.lock() {
                        guard.streams.push(Arc::downgrade(&stream));
                    }
                    let config = self.config.clone();
                    let state = Arc::clone(&state);
                    thread::spawn(move || {
                        if accept_peer(stream, config, state.clone()).is_err() {
                            if let Ok(guard) = state.lock() {
                                guard.metrics.inner.failed_handshakes.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                Err(error) => return Err(TransportError::Io(error)),
            }
        }
    }
}

pub struct RelayServerHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<(), TransportError>>>,
}

impl RelayServerHandle {
    pub fn shutdown(&self) { self.shutdown.store(true, Ordering::Release); }

    pub fn join(mut self) -> Result<(), TransportError> {
        self.join.take().expect("relay server handle already joined").join().unwrap_or(Err(TransportError::Malformed))
    }
}

type SharedStream = Arc<Mutex<TcpStream>>;

struct RelayState {
    pending: HashMap<[u8; 32], PendingCircuit>,
    active: usize,
    in_flight_handshakes: usize,
    rate_limits: HashMap<IpAddr, RateWindow>,
    streams: Vec<Weak<Mutex<TcpStream>>>,
    shutting_down: bool,
    metrics: RelayMetrics,
}

impl RelayState {
    fn new(metrics: RelayMetrics) -> Self {
        Self { pending: HashMap::new(), active: 0, in_flight_handshakes: 0, rate_limits: HashMap::new(), streams: Vec::new(), shutting_down: false, metrics }
    }
}

struct PendingCircuit {
    peer_id: [u8; 32],
    stream: SharedStream,
    created_at: Instant,
}

struct RateWindow {
    started_at: Instant,
    attempts: usize,
}

fn reserve_handshake(state: &Arc<Mutex<RelayState>>, ip: IpAddr, limit: usize, max_pending: usize, stream: &SharedStream) -> bool {
    let Ok(mut guard) = state.lock() else { let _ = close_stream(stream); return false; };
    if guard.shutting_down || guard.in_flight_handshakes >= max_pending {
        let _ = write_status(stream, REJECTED_CAPACITY);
        let _ = close_stream(stream);
        return false;
    }
    let now = Instant::now();
    guard.rate_limits.retain(|_, window| now.duration_since(window.started_at) < Duration::from_secs(60));
    let window = guard.rate_limits.entry(ip).or_insert(RateWindow { started_at: now, attempts: 0 });
    if window.attempts >= limit {
        guard.metrics.inner.rate_limited_connections.fetch_add(1, Ordering::Relaxed);
        let _ = write_status(stream, REJECTED_RATE_LIMIT);
        let _ = close_stream(stream);
        return false;
    }
    window.attempts += 1;
    guard.in_flight_handshakes += 1;
    true
}

fn accept_peer(stream: SharedStream, config: RelayConfig, state: Arc<Mutex<RelayState>>) -> Result<(), TransportError> {
    set_timeouts(&stream, config.handshake_timeout)?;
    let join = read_join(&stream);
    if let Ok(mut guard) = state.lock() { guard.in_flight_handshakes = guard.in_flight_handshakes.saturating_sub(1); }
    let (circuit_id, peer_id) = join?;
    set_timeouts(&stream, config.idle_timeout)?;
    let mut state_guard = state.lock().map_err(|_| TransportError::Malformed)?;
    if state_guard.shutting_down {
        write_status(&stream, REJECTED_SHUTTING_DOWN)?;
        return Err(TransportError::HandshakeRejected(REJECTED_SHUTTING_DOWN));
    }
    let now = Instant::now();
    let expired = state_guard.pending.iter().filter(|(_, pending)| now.duration_since(pending.created_at) > config.handshake_timeout).map(|(id, _)| *id).collect::<Vec<_>>();
    for id in expired {
        if let Some(pending) = state_guard.pending.remove(&id) { let _ = close_stream(&pending.stream); }
    }
    if let Some(pending) = state_guard.pending.remove(&circuit_id) {
        if pending.peer_id == peer_id {
            write_status(&stream, REJECTED_DUPLICATE)?;
            return Err(TransportError::HandshakeRejected(REJECTED_DUPLICATE));
        }
        if state_guard.active >= config.max_circuits {
            write_status(&stream, REJECTED_CAPACITY)?;
            state_guard.pending.insert(circuit_id, pending);
            return Err(TransportError::HandshakeRejected(REJECTED_CAPACITY));
        }
        write_status(&stream, ACCEPTED)?;
        state_guard.active += 1;
        state_guard.metrics.inner.completed_handshakes.fetch_add(2, Ordering::Relaxed);
        state_guard.metrics.inner.active_circuits.fetch_add(1, Ordering::Relaxed);
        let active = Arc::new(AtomicBool::new(false));
        let budget = Arc::new(CircuitBudget { used: AtomicU64::new(0), limit: config.max_circuit_bytes });
        let left = Arc::clone(&pending.stream);
        let right = Arc::clone(&stream);
        let cleanup = Arc::clone(&state);
        let cleanup_for_reverse = Arc::clone(&state);
        let config_for_forward = config.clone();
        let active_for_forward = Arc::clone(&active);
        let budget_for_forward = Arc::clone(&budget);
        drop(state_guard);
        thread::spawn(move || forward(left, right, config_for_forward, cleanup, active_for_forward, budget_for_forward));
        let left = Arc::clone(&pending.stream);
        let right = Arc::clone(&stream);
        thread::spawn(move || forward(right, left, config, cleanup_for_reverse, active, budget));
        return Ok(());
    }
    if state_guard.pending.len() + state_guard.active >= config.max_circuits || state_guard.pending.len() >= config.max_pending_handshakes {
        write_status(&stream, REJECTED_CAPACITY)?;
        return Err(TransportError::HandshakeRejected(REJECTED_CAPACITY));
    }
    write_status(&stream, ACCEPTED)?;
    state_guard.pending.insert(circuit_id, PendingCircuit { peer_id, stream, created_at: now });
    Ok(())
}

struct CircuitBudget {
    used: AtomicU64,
    limit: u64,
}

fn forward(source: SharedStream, destination: SharedStream, config: RelayConfig, state: Arc<Mutex<RelayState>>, released: Arc<AtomicBool>, budget: Arc<CircuitBudget>) {
    let mut reader = match source.lock().ok().and_then(|stream| stream.try_clone().ok()) { Some(reader) => reader, None => return };
    let mut writer = match destination.lock().ok().and_then(|stream| stream.try_clone().ok()) { Some(writer) => writer, None => return };
    let result = loop {
        let frame = match read_frame(&mut reader, config.max_frame_size) { Ok(frame) => frame, Err(error) => break error };
        if !reserve_bytes(&budget, frame.len() as u64) { break TransportError::FrameTooLarge; }
        if let Err(error) = write_frame(&mut writer, &frame, config.max_frame_size) { break error; }
        if let Ok(guard) = state.lock() {
            guard.metrics.inner.forwarded_frames.fetch_add(1, Ordering::Relaxed);
            guard.metrics.inner.forwarded_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
    };
    let _ = result;
    if let Ok(stream) = destination.lock() { let _ = stream.shutdown(Shutdown::Both); }
    if let Ok(stream) = source.lock() { let _ = stream.shutdown(Shutdown::Both); }
    if !released.swap(true, Ordering::SeqCst) {
        if let Ok(mut guard) = state.lock() {
            guard.active = guard.active.saturating_sub(1);
            guard.metrics.inner.active_circuits.fetch_sub(1, Ordering::Relaxed);
            guard.metrics.inner.closed_circuits.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn reserve_bytes(budget: &CircuitBudget, bytes: u64) -> bool {
    let mut current = budget.used.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(bytes) else { return false; };
        if next > budget.limit { return false; }
        match budget.used.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn set_timeouts(stream: &SharedStream, timeout: Duration) -> Result<(), TransportError> {
    let stream = stream.lock().map_err(|_| TransportError::Malformed)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(())
}

fn close_stream(stream: &SharedStream) -> Result<(), TransportError> {
    stream.lock().map_err(|_| TransportError::Malformed)?.shutdown(Shutdown::Both).map_err(TransportError::Io)
}

fn begin_shutdown(state: &Arc<Mutex<RelayState>>) {
    let pending = {
        let Ok(mut guard) = state.lock() else { return; };
        guard.shutting_down = true;
        guard.pending.drain().map(|(_, pending)| pending.stream).collect::<Vec<_>>()
    };
    for stream in pending { let _ = close_stream(&stream); }
}

fn wait_for_shutdown(state: &Arc<Mutex<RelayState>>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let active = state.lock().map(|guard| guard.active).unwrap_or(0);
        if active == 0 { return; }
        if Instant::now() >= deadline {
            let streams = state.lock().map(|guard| guard.streams.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()).unwrap_or_default();
            for stream in streams { let _ = close_stream(&stream); }
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn join(stream: &TcpStream, circuit_id: [u8; 32], peer_id: [u8; 32]) -> Result<(), TransportError> {
    let mut stream = stream.try_clone()?;
    let mut hello = Vec::with_capacity(8 + 1 + 64);
    hello.extend_from_slice(MAGIC);
    hello.push(JOIN);
    hello.extend_from_slice(&circuit_id);
    hello.extend_from_slice(&peer_id);
    stream.write_all(&hello)?;
    let mut status = [0u8; 1];
    stream.read_exact(&mut status)?;
    if status[0] != ACCEPTED { return Err(TransportError::HandshakeRejected(status[0])); }
    Ok(())
}

fn read_join(stream: &SharedStream) -> Result<([u8; 32], [u8; 32]), TransportError> {
    let mut stream = stream.lock().map_err(|_| TransportError::Malformed)?.try_clone()?;
    let mut magic = [0u8; 8]; stream.read_exact(&mut magic)?;
    if &magic != MAGIC { return Err(TransportError::Malformed); }
    let mut kind = [0u8; 1]; stream.read_exact(&mut kind)?;
    if kind[0] != JOIN { return Err(TransportError::Malformed); }
    let mut circuit_id = [0u8; 32]; let mut peer_id = [0u8; 32];
    stream.read_exact(&mut circuit_id)?; stream.read_exact(&mut peer_id)?;
    Ok((circuit_id, peer_id))
}

fn write_status(stream: &SharedStream, status: u8) -> Result<(), TransportError> {
    let mut stream = stream.lock().map_err(|_| TransportError::Malformed)?;
    stream.write_all(&[status]).map_err(TransportError::Io)
}

fn write_frame<W: Write>(writer: &mut W, frame: &[u8], max_frame_size: usize) -> Result<(), TransportError> {
    if frame.len() > max_frame_size || frame.len() > u32::MAX as usize { return Err(TransportError::FrameTooLarge); }
    writer.write_all(&(frame.len() as u32).to_le_bytes())?;
    writer.write_all(frame)?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R, max_frame_size: usize) -> Result<Vec<u8>, TransportError> {
    let mut length = [0u8; 4]; reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > max_frame_size || length > MAX_FRAME_SIZE { return Err(TransportError::FrameTooLarge); }
    let mut frame = vec![0u8; length]; reader.read_exact(&mut frame)?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_frames_are_bounded_and_round_trip() {
        let frame = vec![7u8; 128];
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &frame, 256).unwrap();
        assert_eq!(read_frame(&mut encoded.as_slice(), 256).unwrap(), frame);
        assert!(matches!(write_frame(&mut Vec::new(), &[0u8; 257], 256), Err(TransportError::FrameTooLarge)));
    }

    #[test]
    fn circuit_budget_is_total_and_bounded() {
        let budget = CircuitBudget { used: AtomicU64::new(0), limit: 5 };
        assert!(reserve_bytes(&budget, 3));
        assert!(!reserve_bytes(&budget, 3));
        assert!(reserve_bytes(&budget, 2));
        assert!(!reserve_bytes(&budget, 1));
    }

    #[test]
    fn paired_clients_exchange_opaque_frames() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind relay test listener: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let server = RelayServer::new(RelayConfig { max_circuits: 4, idle_timeout: Duration::from_secs(5), ..RelayConfig::default() });
        let metrics = server.metrics();
        let handle = server.start(listener);
        let config = RelayConfig { idle_timeout: Duration::from_secs(5), ..RelayConfig::default() };
        let circuit = [4u8; 32];
        let mut left = RelayClient::connect(address, circuit, [1u8; 32], &config).unwrap();
        let mut right = RelayClient::connect(address, circuit, [2u8; 32], &config).unwrap();
        left.send_frame(b"opaque-block").unwrap();
        assert_eq!(right.recv_frame().unwrap(), b"opaque-block");
        right.send_frame(b"response").unwrap();
        assert_eq!(left.recv_frame().unwrap(), b"response");
        left.shutdown().unwrap();
        right.shutdown().unwrap();
        handle.shutdown();
        handle.join().unwrap();
        assert_eq!(metrics.snapshot().active_circuits, 0);
    }
}
