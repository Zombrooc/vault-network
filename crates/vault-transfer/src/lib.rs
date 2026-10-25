//! Receives encrypted object material and commits it only after full validation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::ToSocketAddrs;
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use vault_core::{inspect_encrypted_manifest, Container, EncryptedBlock, ObjectInfo, ObjectId, TransferCheckpoint, VaultError};
use vault_identity::ParticipationKey;
use vault_protocol::{manifest_signing_bytes, permission, CapabilityContext, Hello, Message, ProtocolError, Session};
use vault_sharing::InvitationPayload;
use vault_transport::{RelayClient, RelayConfig, TransportError};
use zeroize::{Zeroize, Zeroizing};

const MAX_BLOCKS: usize = 4 * 1024 * 1024;
const PARALLEL_BATCH_BLOCKS: usize = 32;

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("invitation is invalid")]
    InvalidInvitation,
    #[error("message does not match the transfer scope")]
    ScopeMismatch,
    #[error("manifest is invalid or arrived more than once")]
    InvalidManifest,
    #[error("block is invalid or outside the manifest")]
    InvalidBlock,
    #[error("manifest must be received first")]
    ManifestRequired,
    #[error("transfer is incomplete: {0} blocks remain")]
    Incomplete(usize),
    #[error("transfer protocol error: {0}")]
    Protocol(#[from] vault_protocol::ProtocolError),
    #[error("relay transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("container error: {0}")]
    Container(#[from] VaultError),
    #[error("peer requested an unknown block")]
    UnknownBlock,
    #[error("no relay source was provided")]
    NoSources,
    #[error("transfer state is unavailable")]
    StateUnavailable,
}

pub struct DownloadSession {
    object_id: ObjectId,
    manifest_id: [u8; 32],
    cek: Zeroizing<[u8; 32]>,
    capability: vault_protocol::Capability,
    participant: ParticipationKey,
    owner_pubkey: [u8; 32],
    manifest_signature: [u8; 64],
    manifest_nonce: Option<[u8; 24]>,
    manifest_ciphertext: Option<Vec<u8>>,
    expected_blocks: Option<Vec<[u8; 32]>>,
    expected_block_set: BTreeSet<[u8; 32]>,
    blocks: BTreeMap<[u8; 32], Vec<u8>>,
}

impl Drop for DownloadSession {
    fn drop(&mut self) {
        self.cek.zeroize();
        for bytes in self.blocks.values_mut() { bytes.zeroize(); }
    }
}

impl DownloadSession {
    pub fn from_invitation(payload: &InvitationPayload) -> Result<Self, TransferError> {
        payload.validate().map_err(|_| TransferError::InvalidInvitation)?;
        let owner = VerifyingKey::from_bytes(&payload.owner_pubkey).map_err(|_| TransferError::InvalidInvitation)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| TransferError::InvalidInvitation)?.as_secs();
        payload.capability.validate(&owner, &CapabilityContext { swarm_id: &payload.swarm_id, object_id: Some(&payload.object_id), required_perm: permission::DOWNLOAD, revoked_epoch: 0, now }).map_err(|_| TransferError::InvalidInvitation)?;
        Ok(Self {
            object_id: ObjectId::from_bytes(payload.object_id),
            manifest_id: payload.manifest_id,
            cek: Zeroizing::new(payload.cek),
            capability: payload.capability.clone(),
            participant: ParticipationKey::from_secret_bytes(payload.participation_secret),
            owner_pubkey: payload.owner_pubkey,
            manifest_signature: payload.manifest_signature,
            manifest_nonce: None,
            manifest_ciphertext: None,
            expected_blocks: None,
            expected_block_set: BTreeSet::new(),
            blocks: BTreeMap::new(),
        })
    }

    pub fn resume_from_invitation(container: &Container, payload: &InvitationPayload) -> Result<Self, TransferError> {
        let mut session = Self::from_invitation(payload)?;
        let checkpoint = match container.load_transfer_checkpoint(session.object_id) {
            Ok(checkpoint) => checkpoint,
            Err(VaultError::Integrity) => { let _ = container.clear_transfer_checkpoint(session.object_id); None }
            Err(error) => return Err(TransferError::Container(error)),
        };
        let Some(checkpoint) = checkpoint else { return Ok(session); };
        if checkpoint.manifest_id != session.manifest_id || checkpoint.cek != *session.cek {
            container.clear_transfer_checkpoint(session.object_id)?;
            return Ok(session);
        }
        let manifest_id = checkpoint.manifest_id;
        let manifest_nonce = checkpoint.manifest_nonce;
        let manifest_ciphertext = checkpoint.manifest_ciphertext.clone();
        let blocks = checkpoint.blocks.clone();
        let manifest_signature = session.manifest_signature;
        session.accept_manifest(*session.object_id.as_bytes(), manifest_id, manifest_nonce, manifest_signature, manifest_ciphertext)?;
        for block in blocks { session.accept_block(block.id, block.bytes)?; }
        Ok(session)
    }

    pub fn peer_id(&self) -> [u8; 32] { self.participant.peer_id() }

    pub fn download<A: ToSocketAddrs>(self, address: A, config: &RelayConfig, container: &Container) -> Result<ObjectInfo, TransferError> {
        let mut session = self;
        session.receive_from_source(address, config, container)?;
        session.commit(container)
    }

    pub fn download_from_sources(self, addresses: &[String], config: &RelayConfig, container: &Container) -> Result<ObjectInfo, TransferError> {
        if addresses.is_empty() { return Err(TransferError::NoSources); }
        let source_count = addresses.len().min(8);
        let shared = Arc::new((
            Mutex::new(SharedDownload { session: self, reserved: BTreeSet::new(), active_workers: source_count }),
            Condvar::new(),
        ));
        let errors = std::thread::scope(|scope| {
            let handles = addresses.iter().take(source_count).cloned().map(|address| {
                let shared = Arc::clone(&shared);
                let config = config.clone();
                scope.spawn(move || run_parallel_source(address, config, shared, container))
            }).collect::<Vec<_>>();
            handles.into_iter().map(|handle| handle.join().unwrap_or(Err(TransferError::StateUnavailable))).filter_map(Result::err).collect::<Vec<_>>()
        });
        let session_state = Arc::try_unwrap(shared).map_err(|_| TransferError::StateUnavailable)?.0.into_inner().map_err(|_| TransferError::StateUnavailable)?;
        if !session_state.session.is_complete() {
            return Err(errors.into_iter().next().unwrap_or_else(|| TransferError::Incomplete(session_state.session.missing_count().unwrap_or(0))));
        }
        session_state.session.commit(container)
    }

    fn receive_from_source<A: ToSocketAddrs>(&mut self, address: A, config: &RelayConfig, container: &Container) -> Result<(), TransferError> {
        let mut relay = RelayClient::connect(address, self.capability.swarm_id, self.participant.peer_id(), config)?;
        let mut challenge = [0u8; 32]; OsRng.fill_bytes(&mut challenge);
        let hello = Hello::with_response(self.capability.clone(), challenge, self.participant.sign_challenge(&challenge));
        send_message(&mut relay, &Message::Hello(hello))?;
        self.accept_message(receive_message(&mut relay)?)?;
        self.persist_checkpoint(container)?;
        loop {
            let missing = self.missing_blocks(vault_protocol::MAX_BLOCKS_PER_MESSAGE);
            if missing.is_empty() { break; }
            let requested = missing.len();
            send_message(&mut relay, &Message::RequestBlocks { object_id: *self.object_id.as_bytes(), block_ids: missing })?;
            for _ in 0..requested { self.accept_message(receive_message(&mut relay)?)?; }
            self.persist_checkpoint(container)?;
        }
        send_message(&mut relay, &Message::Cancel { request_id: 0 })?;
        relay.shutdown()?;
        Ok(())
    }

    pub fn accept_message(&mut self, message: Message) -> Result<(), TransferError> {
        match message {
            Message::Manifest { object_id, manifest_id, nonce, owner_signature, bytes } => self.accept_manifest(object_id, manifest_id, nonce, owner_signature, bytes),
            Message::Block { block_id, bytes } => self.accept_block(block_id, bytes),
            _ => Err(TransferError::Protocol(vault_protocol::ProtocolError::InvalidState)),
        }
    }

    pub fn accept_manifest(&mut self, object_id: [u8; 16], manifest_id: [u8; 32], nonce: [u8; 24], owner_signature: [u8; 64], ciphertext: Vec<u8>) -> Result<(), TransferError> {
        if object_id != *self.object_id.as_bytes() || manifest_id != self.manifest_id { return Err(TransferError::ScopeMismatch); }
        let owner = VerifyingKey::from_bytes(&self.owner_pubkey).map_err(|_| TransferError::InvalidManifest)?;
        if owner.verify(&manifest_signing_bytes(&manifest_id, &self.capability.swarm_id, &object_id), &Signature::from_bytes(&owner_signature)).is_err() { return Err(TransferError::InvalidManifest); }
        if ciphertext.len() < 16 || ciphertext.len() > vault_protocol::MAX_MANIFEST_BYTES { return Err(TransferError::InvalidManifest); }
        if self.expected_blocks.is_some() {
            if self.manifest_nonce == Some(nonce) && self.manifest_ciphertext.as_deref() == Some(ciphertext.as_slice()) { return Ok(()); }
            return Err(TransferError::InvalidManifest);
        }
        let manifest = inspect_encrypted_manifest(self.object_id, self.manifest_id, *self.cek, nonce, &ciphertext)?;
        if manifest.block_ids.is_empty() || manifest.block_ids.len() > MAX_BLOCKS { return Err(TransferError::InvalidManifest); }
        let block_set = manifest.block_ids.iter().copied().collect::<BTreeSet<_>>();
        if block_set.len() != manifest.block_ids.len() { return Err(TransferError::InvalidManifest); }
        self.expected_block_set = block_set;
        self.expected_blocks = Some(manifest.block_ids);
        self.manifest_nonce = Some(nonce);
        self.manifest_ciphertext = Some(ciphertext);
        Ok(())
    }

    pub fn accept_block(&mut self, block_id: [u8; 32], bytes: Vec<u8>) -> Result<(), TransferError> {
        self.expected_blocks.as_ref().ok_or(TransferError::ManifestRequired)?;
        if bytes.len() < 16 || bytes.len() > vault_protocol::MAX_BLOCK_BYTES || !self.expected_block_set.contains(&block_id) || *blake3::hash(&bytes).as_bytes() != block_id { return Err(TransferError::InvalidBlock); }
        if let Some(previous) = self.blocks.get(&block_id) {
            if previous != &bytes { return Err(TransferError::InvalidBlock); }
            return Ok(());
        }
        self.blocks.insert(block_id, bytes);
        Ok(())
    }

    pub fn received_blocks(&self) -> usize { self.blocks.len() }

    pub fn total_blocks(&self) -> Option<usize> { self.expected_blocks.as_ref().map(Vec::len) }

    fn missing_count(&self) -> Option<usize> { self.expected_blocks.as_ref().map(|expected| expected.iter().filter(|id| !self.blocks.contains_key(*id)).count()) }

    fn is_complete(&self) -> bool { self.missing_count() == Some(0) }

    pub fn missing_blocks(&self, limit: usize) -> Vec<[u8; 32]> {
        self.expected_blocks.as_deref().unwrap_or(&[]).iter().filter(|id| !self.blocks.contains_key(*id)).take(limit).copied().collect()
    }

    pub fn commit(self, container: &Container) -> Result<ObjectInfo, TransferError> {
        let expected = self.expected_blocks.as_ref().ok_or(TransferError::ManifestRequired)?;
        let missing = expected.iter().filter(|id| !self.blocks.contains_key(*id)).count();
        if missing != 0 { return Err(TransferError::Incomplete(missing)); }
        let blocks = expected.iter().map(|id| EncryptedBlock { id: *id, bytes: self.blocks.get(id).expect("checked above").clone() }).collect::<Vec<_>>();
        let object_id = self.object_id;
        let result = container.import_encrypted_object(object_id, self.manifest_id, *self.cek, self.manifest_nonce.ok_or(TransferError::ManifestRequired)?, self.manifest_ciphertext.as_deref().ok_or(TransferError::ManifestRequired)?, &blocks).map_err(TransferError::from);
        if result.is_ok() { let _ = container.clear_transfer_checkpoint(object_id); }
        result
    }

    fn persist_checkpoint(&self, container: &Container) -> Result<(), TransferError> {
        let (Some(manifest_nonce), Some(manifest_ciphertext)) = (self.manifest_nonce, self.manifest_ciphertext.as_ref()) else { return Ok(()); };
        let checkpoint = TransferCheckpoint { cek: *self.cek, manifest_id: self.manifest_id, manifest_nonce, manifest_ciphertext: manifest_ciphertext.clone(), blocks: self.blocks.iter().map(|(id, bytes)| EncryptedBlock { id: *id, bytes: bytes.clone() }).collect() };
        container.save_transfer_checkpoint(self.object_id, &checkpoint).map_err(TransferError::from)
    }
}

struct SharedDownload {
    session: DownloadSession,
    reserved: BTreeSet<[u8; 32]>,
    active_workers: usize,
}

fn run_parallel_source(address: String, config: RelayConfig, shared: Arc<(Mutex<SharedDownload>, Condvar)>, container: &Container) -> Result<(), TransferError> {
    let mut owned = BTreeSet::new();
    let result = (|| {
        let mut relay = RelayClient::connect(address.as_str(), shared_session_scope(&shared)?, shared_peer_id(&shared)?, &config)?;
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        let hello = {
            let (lock, _) = &*shared;
            let state = lock.lock().map_err(|_| TransferError::StateUnavailable)?;
            Hello::with_response(state.session.capability.clone(), challenge, state.session.participant.sign_challenge(&challenge))
        };
        send_message(&mut relay, &Message::Hello(hello))?;
        let manifest = receive_message(&mut relay)?;
        {
            let (lock, condition) = &*shared;
            let mut state = lock.lock().map_err(|_| TransferError::StateUnavailable)?;
            state.session.accept_message(manifest)?;
            state.session.persist_checkpoint(container)?;
            condition.notify_all();
        }

        loop {
            let requested = {
                let (lock, condition) = &*shared;
                let mut state = lock.lock().map_err(|_| TransferError::StateUnavailable)?;
                loop {
                    if state.session.is_complete() { break Vec::new(); }
                    let batch_limit = parallel_batch_limit(state.session.total_blocks(), state.active_workers);
                    let mut missing = state.session.missing_blocks(batch_limit);
                    missing.retain(|block_id| !state.reserved.contains(block_id));
                    if !missing.is_empty() {
                        for block_id in &missing { state.reserved.insert(*block_id); owned.insert(*block_id); }
                        break missing;
                    }
                    if state.active_workers <= 1 {
                        return Err(if state.session.total_blocks().is_some() { TransferError::Incomplete(state.session.missing_count().unwrap_or(0)) } else { TransferError::ManifestRequired });
                    }
                    state = condition.wait_timeout(state, Duration::from_millis(100)).map_err(|_| TransferError::StateUnavailable)?.0;
                }
            };
            if requested.is_empty() { break; }
            send_message(&mut relay, &Message::RequestBlocks { object_id: shared_object_id(&shared)?, block_ids: requested.clone() })?;
            for _ in &requested {
                let result = match receive_message(&mut relay)? {
                    Message::Block { block_id, bytes } => {
                        let (lock, condition) = &*shared;
                        let mut state = lock.lock().map_err(|_| TransferError::StateUnavailable)?;
                        let result = state.session.accept_block(block_id, bytes);
                        if owned.remove(&block_id) { state.reserved.remove(&block_id); }
                        if result.is_ok() { state.session.persist_checkpoint(container)?; }
                        condition.notify_all();
                        result
                    }
                    _ => Err(TransferError::Protocol(ProtocolError::InvalidState)),
                };
                result?;
            }
        }
        let _ = send_message(&mut relay, &Message::Cancel { request_id: 0 });
        let _ = relay.shutdown();
        Ok(())
    })();
    release_reserved(&shared, &mut owned);
    if let Ok(mut state) = shared.0.lock() {
        state.active_workers = state.active_workers.saturating_sub(1);
        shared.1.notify_all();
    }
    result
}

fn release_reserved(shared: &Arc<(Mutex<SharedDownload>, Condvar)>, owned: &mut BTreeSet<[u8; 32]>) {
    let ids = std::mem::take(owned);
    if let Ok(mut state) = shared.0.lock() {
        for block_id in ids { state.reserved.remove(&block_id); }
        shared.1.notify_all();
    }
}

fn shared_session_scope(shared: &Arc<(Mutex<SharedDownload>, Condvar)>) -> Result<[u8; 32], TransferError> {
    shared.0.lock().map(|state| state.session.capability.swarm_id).map_err(|_| TransferError::StateUnavailable)
}

fn shared_peer_id(shared: &Arc<(Mutex<SharedDownload>, Condvar)>) -> Result<[u8; 32], TransferError> {
    shared.0.lock().map(|state| state.session.participant.peer_id()).map_err(|_| TransferError::StateUnavailable)
}

fn shared_object_id(shared: &Arc<(Mutex<SharedDownload>, Condvar)>) -> Result<[u8; 16], TransferError> {
    shared.0.lock().map(|state| *state.session.object_id.as_bytes()).map_err(|_| TransferError::StateUnavailable)
}

fn parallel_batch_limit(total_blocks: Option<usize>, active_workers: usize) -> usize {
    total_blocks.unwrap_or(1).div_ceil(active_workers.max(1)).clamp(1, PARALLEL_BATCH_BLOCKS)
}

pub struct Seeder {
    object_id: ObjectId,
    object: vault_core::EncryptedObject,
    manifest_signature: [u8; 64],
}

impl Seeder {
    pub fn from_container(container: &Container, object_id: ObjectId, manifest_signature: [u8; 64]) -> Result<Self, TransferError> {
        Ok(Self { object_id, object: container.read_encrypted_object(object_id)?, manifest_signature })
    }

    pub fn serve<A: ToSocketAddrs>(&self, address: A, circuit_id: [u8; 32], peer_id: [u8; 32], config: &RelayConfig, owner_pubkey: [u8; 32], swarm_id: [u8; 32], revoked_epoch: u64, now: u64) -> Result<usize, TransferError> {
        let mut relay = RelayClient::connect(address, circuit_id, peer_id, config)?;
        let result = self.serve_once(&mut relay, owner_pubkey, swarm_id, revoked_epoch, now);
        let _ = relay.shutdown();
        result
    }

    pub fn serve_until<A: ToSocketAddrs + Clone>(&self, address: A, circuit_id: [u8; 32], peer_id: [u8; 32], config: &RelayConfig, owner_pubkey: [u8; 32], swarm_id: [u8; 32], revoked_epoch: u64, now: u64, cancel: &AtomicBool) -> Result<usize, TransferError> {
        let epoch = AtomicU64::new(revoked_epoch);
        self.serve_until_with_revocation(address, circuit_id, peer_id, config, owner_pubkey, swarm_id, &epoch, now, cancel)
    }

    pub fn serve_until_with_revocation<A: ToSocketAddrs + Clone>(&self, address: A, circuit_id: [u8; 32], peer_id: [u8; 32], config: &RelayConfig, owner_pubkey: [u8; 32], swarm_id: [u8; 32], revoked_epoch: &AtomicU64, now: u64, cancel: &AtomicBool) -> Result<usize, TransferError> {
        let mut total = 0;
        while cancel.load(Ordering::Acquire) {
            let mut relay = RelayClient::connect(address.clone(), circuit_id, peer_id, config)?;
            let result = self.serve_connected(&mut relay, owner_pubkey, swarm_id, revoked_epoch, now, Some(cancel));
            let _ = relay.shutdown();
            match result {
                Ok(sent) => total += sent,
                Err(_) if !cancel.load(Ordering::Acquire) => return Ok(total),
                Err(error) => return Err(error),
            }
        }
        Ok(total)
    }

    pub fn serve_once(&self, relay: &mut RelayClient, owner_pubkey: [u8; 32], swarm_id: [u8; 32], revoked_epoch: u64, now: u64) -> Result<usize, TransferError> {
        let epoch = AtomicU64::new(revoked_epoch);
        self.serve_connected(relay, owner_pubkey, swarm_id, &epoch, now, None)
    }

    fn serve_connected(&self, relay: &mut RelayClient, owner_pubkey: [u8; 32], swarm_id: [u8; 32], revoked_epoch: &AtomicU64, now: u64, cancel: Option<&AtomicBool>) -> Result<usize, TransferError> {
        let owner = VerifyingKey::from_bytes(&owner_pubkey).map_err(|_| TransferError::InvalidInvitation)?;
        let context = CapabilityContext { swarm_id: &swarm_id, object_id: Some(self.object_id.as_bytes()), required_perm: permission::DOWNLOAD, revoked_epoch: revoked_epoch.load(Ordering::Acquire), now };
        let mut session = Session::new();
        let hello = receive_message(relay)?;
        session.receive(hello, &owner, &context)?;
        send_message(relay, &Message::Manifest { object_id: *self.object_id.as_bytes(), manifest_id: self.object.manifest_id, nonce: self.object.manifest_nonce, owner_signature: self.manifest_signature, bytes: self.object.manifest_ciphertext.clone() })?;
        let mut sent = 0;
        loop {
            if cancel.is_some_and(|flag| !flag.load(Ordering::Acquire)) { return Ok(sent); }
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| TransferError::InvalidInvitation)?.as_secs();
            let context = CapabilityContext { swarm_id: &swarm_id, object_id: Some(self.object_id.as_bytes()), required_perm: permission::DOWNLOAD, revoked_epoch: revoked_epoch.load(Ordering::Acquire), now };
            match receive_message(relay)? {
                Message::RequestBlocks { object_id, block_ids } => {
                    let message = Message::RequestBlocks { object_id, block_ids: block_ids.clone() };
                    session.receive(message, &owner, &context)?;
                    for block_id in block_ids {
                        let block = self.object.blocks.iter().find(|block| block.id == block_id).ok_or(TransferError::UnknownBlock)?;
                        send_message(relay, &Message::Block { block_id: block.id, bytes: block.bytes.clone() })?;
                        sent += 1;
                    }
                }
                Message::Cancel { request_id } => {
                    session.receive(Message::Cancel { request_id }, &owner, &context)?;
                    break;
                }
                message => {
                    session.receive(message, &owner, &context)?;
                    return Err(TransferError::Protocol(ProtocolError::InvalidState));
                }
            }
        }
        Ok(sent)
    }

}

fn send_message(relay: &mut RelayClient, message: &Message) -> Result<(), TransferError> {
    relay.send_frame(&message.encode()?)?;
    Ok(())
}

fn receive_message(relay: &mut RelayClient) -> Result<Message, TransferError> {
    Ok(Message::decode(&relay.recv_frame()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unlisted_or_tampered_blocks() {
        let bytes = b"ciphertext-block!".to_vec();
        let block_id = *blake3::hash(&bytes).as_bytes();
        let mut session = DownloadSession {
            object_id: ObjectId::from_bytes([1; 16]),
            manifest_id: [2; 32],
            cek: Zeroizing::new([3; 32]),
            capability: vault_protocol::Capability::new([6; 32], Some([1; 16]), [7; 32], permission::DOWNLOAD, 0, u64::MAX, 0),
            participant: ParticipationKey::from_secret_bytes([8; 32]),
            owner_pubkey: [9; 32],
            manifest_signature: [5; 64],
            manifest_nonce: Some([4; 24]),
            manifest_ciphertext: Some(vec![5]),
            expected_blocks: Some(vec![block_id]),
            expected_block_set: [block_id].into_iter().collect(),
            blocks: BTreeMap::new(),
        };
        assert!(matches!(session.accept_block([9; 32], bytes.clone()), Err(TransferError::InvalidBlock)));
        assert!(matches!(session.accept_block(block_id, b"tampered".to_vec()), Err(TransferError::InvalidBlock)));
        session.accept_block(block_id, bytes).unwrap();
        assert_eq!(session.received_blocks(), 1);
    }

    #[test]
    fn parallel_batches_share_small_objects_between_sources() {
        assert_eq!(parallel_batch_limit(Some(2), 2), 1);
        assert_eq!(parallel_batch_limit(Some(100), 2), PARALLEL_BATCH_BLOCKS);
        assert_eq!(parallel_batch_limit(None, 0), 1);
    }
}

