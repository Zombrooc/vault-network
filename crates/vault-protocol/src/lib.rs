//! Bounded application messages and offline capability validation.
//!
//! Transport adapters must pass complete frames through this crate. No message
//! handler is allowed to allocate from an unchecked length supplied by a peer.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::io::{self, Read, Write};
use thiserror::Error;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024 + 128 * 1024;
pub const MAX_CAPABILITY_BYTES: usize = 512;
pub const MAX_BITMAP_BYTES: usize = 512 * 1024;
pub const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024 + 16;
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BLOCKS_PER_MESSAGE: usize = 256;

pub fn manifest_signing_bytes(manifest_id: &[u8; 32], swarm_id: &[u8; 32], object_id: &[u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 16 + 24);
    bytes.extend_from_slice(b"vault/v1/manifest-signature");
    bytes.extend_from_slice(manifest_id);
    bytes.extend_from_slice(swarm_id);
    bytes.extend_from_slice(object_id);
    bytes
}

pub mod permission {
    pub const DOWNLOAD: u32 = 1 << 0;
    pub const SEED: u32 = 1 << 1;
    pub const DELEGATE: u32 = 1 << 2;
    pub const PUBLISH: u32 = 1 << 3;
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame is too large")]
    FrameTooLarge,
    #[error("frame is truncated or malformed")]
    Malformed,
    #[error("message is not valid in the current handshake state")]
    InvalidState,
    #[error("capability signature is invalid")]
    InvalidCapabilitySignature,
    #[error("capability is expired, not yet valid, revoked, or lacks permission")]
    CapabilityDenied,
    #[error("challenge response is invalid")]
    InvalidChallenge,
    #[error("capability subject does not match the challenge key")]
    SubjectMismatch,
    #[error("requested swarm or object does not match the session")]
    ScopeMismatch,
    #[error("message count exceeds the protocol limit")]
    TooManyItems,
    #[error("block payload exceeds the protocol limit")]
    BlockTooLarge,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl PartialEq for ProtocolError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind()
                    && left.raw_os_error() == right.raw_os_error()
                    && left.to_string() == right.to_string()
            }
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

impl Eq for ProtocolError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub version: u8,
    pub swarm_id: [u8; 32],
    pub object_id: Option<[u8; 16]>,
    pub subject_pubkey: [u8; 32],
    pub perms: u32,
    pub not_before: u64,
    pub expires: u64,
    pub epoch: u64,
    pub owner_sig: [u8; 64],
}

impl Capability {
    pub fn new(swarm_id: [u8; 32], object_id: Option<[u8; 16]>, subject_pubkey: [u8; 32], perms: u32, not_before: u64, expires: u64, epoch: u64) -> Self {
        Self { version: PROTOCOL_VERSION, swarm_id, object_id, subject_pubkey, perms, not_before, expires, epoch, owner_sig: [0u8; 64] }
    }

    pub fn sign(mut self, owner: &SigningKey) -> Self {
        self.owner_sig = owner.sign(&self.unsigned_bytes()).to_bytes();
        self
    }

    pub fn verify_owner(&self, owner: &VerifyingKey) -> Result<(), ProtocolError> {
        let signature = Signature::from_bytes(&self.owner_sig);
        owner.verify(&self.unsigned_bytes(), &signature).map_err(|_| ProtocolError::InvalidCapabilitySignature)
    }

    pub fn validate(&self, owner: &VerifyingKey, context: &CapabilityContext<'_>) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION || self.swarm_id != *context.swarm_id || self.epoch < context.revoked_epoch || self.not_before > context.now || self.expires <= context.now || self.expires <= self.not_before || self.perms & context.required_perm != context.required_perm {
            return Err(ProtocolError::CapabilityDenied);
        }
        if let Some(expected_object) = context.object_id {
            if self.object_id.is_some() && self.object_id != Some(*expected_object) { return Err(ProtocolError::ScopeMismatch); }
        }
        self.verify_owner(owner)
    }

    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 1 + 16 + 32 + 4 + 8 + 8 + 8);
        out.push(self.version); out.extend_from_slice(&self.swarm_id); out.push(u8::from(self.object_id.is_some())); if let Some(object_id) = self.object_id { out.extend_from_slice(&object_id); }
        out.extend_from_slice(&self.subject_pubkey); out.extend_from_slice(&self.perms.to_le_bytes()); out.extend_from_slice(&self.not_before.to_le_bytes()); out.extend_from_slice(&self.expires.to_le_bytes()); out.extend_from_slice(&self.epoch.to_le_bytes()); out
    }

    pub fn encode(&self) -> Vec<u8> { let mut out = self.unsigned_bytes(); out.extend_from_slice(&self.owner_sig); out }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut cursor = Cursor::new(bytes); let version = cursor.u8()?; let swarm_id = cursor.array::<32>()?; let has_object = cursor.u8()?; if has_object > 1 { return Err(ProtocolError::Malformed); } let object_id = if has_object == 1 { Some(cursor.array::<16>()?) } else { None }; let subject_pubkey = cursor.array::<32>()?; let perms = cursor.u32()?; let not_before = cursor.u64()?; let expires = cursor.u64()?; let epoch = cursor.u64()?; let owner_sig = cursor.array::<64>()?; cursor.finish()?; Ok(Self { version, swarm_id, object_id, subject_pubkey, perms, not_before, expires, epoch, owner_sig })
    }
}

pub struct CapabilityContext<'a> {
    pub swarm_id: &'a [u8; 32],
    pub object_id: Option<&'a [u8; 16]>,
    pub required_perm: u32,
    pub revoked_epoch: u64,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub capability: Capability,
    pub challenge: [u8; 32],
    pub challenge_response: [u8; 64],
}

impl Hello {
    pub fn new(capability: Capability, challenge: [u8; 32], participant: &SigningKey) -> Self { Self::with_response(capability, challenge, participant.sign(&challenge).to_bytes()) }

    pub fn with_response(capability: Capability, challenge: [u8; 32], challenge_response: [u8; 64]) -> Self { Self { capability, challenge, challenge_response } }

    pub fn verify_subject(&self) -> Result<(), ProtocolError> {
        let key = VerifyingKey::from_bytes(&self.capability.subject_pubkey).map_err(|_| ProtocolError::SubjectMismatch)?;
        let signature = Signature::from_bytes(&self.challenge_response);
        key.verify(&self.challenge, &signature).map_err(|_| ProtocolError::InvalidChallenge)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    BlockBitmap { object_id: [u8; 16], bitmap: Vec<u8> },
    Manifest { object_id: [u8; 16], manifest_id: [u8; 32], nonce: [u8; 24], owner_signature: [u8; 64], bytes: Vec<u8> },
    RequestBlocks { object_id: [u8; 16], block_ids: Vec<[u8; 32]> },
    Block { block_id: [u8; 32], bytes: Vec<u8> },
    Have { object_id: [u8; 16], block_ids: Vec<[u8; 32]> },
    Cancel { request_id: u64 },
    RevokeNotice { swarm_id: [u8; 32], epoch: u64, owner_sig: [u8; 64] },
    Error { code: u16 },
}

impl Message {
    const HELLO: u8 = 1;
    const BLOCK_BITMAP: u8 = 2;
    const REQUEST_BLOCKS: u8 = 3;
    const BLOCK: u8 = 4;
    const HAVE: u8 = 5;
    const CANCEL: u8 = 6;
    const REVOKE_NOTICE: u8 = 7;
    const ERROR: u8 = 8;
    const MANIFEST: u8 = 9;

    pub fn revoke_notice(swarm_id: [u8; 32], epoch: u64, owner: &SigningKey) -> Self {
        Self::RevokeNotice { swarm_id, epoch, owner_sig: owner.sign(&revoke_bytes(&swarm_id, epoch)).to_bytes() }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::new();
        match self {
            Self::Hello(hello) => { out.push(Self::HELLO); let capability = hello.capability.encode(); put_bytes(&mut out, &capability)?; out.extend_from_slice(&hello.challenge); out.extend_from_slice(&hello.challenge_response); }
            Self::BlockBitmap { object_id, bitmap } => { if bitmap.len() > MAX_BITMAP_BYTES { return Err(ProtocolError::FrameTooLarge); } out.push(Self::BLOCK_BITMAP); out.extend_from_slice(object_id); put_bytes(&mut out, bitmap)?; }
            Self::Manifest { object_id, manifest_id, nonce, owner_signature, bytes } => { if bytes.len() > MAX_MANIFEST_BYTES { return Err(ProtocolError::FrameTooLarge); } out.push(Self::MANIFEST); out.extend_from_slice(object_id); out.extend_from_slice(manifest_id); out.extend_from_slice(nonce); out.extend_from_slice(owner_signature); put_bytes(&mut out, bytes)?; }
            Self::RequestBlocks { object_id, block_ids } => { check_count(block_ids.len())?; out.push(Self::REQUEST_BLOCKS); out.extend_from_slice(object_id); put_u16(&mut out, block_ids.len()); for block_id in block_ids { out.extend_from_slice(block_id); } }
            Self::Block { block_id, bytes } => { if bytes.len() > MAX_BLOCK_BYTES { return Err(ProtocolError::BlockTooLarge); } out.push(Self::BLOCK); out.extend_from_slice(block_id); put_bytes(&mut out, bytes)?; }
            Self::Have { object_id, block_ids } => { check_count(block_ids.len())?; out.push(Self::HAVE); out.extend_from_slice(object_id); put_u16(&mut out, block_ids.len()); for block_id in block_ids { out.extend_from_slice(block_id); } }
            Self::Cancel { request_id } => { out.push(Self::CANCEL); out.extend_from_slice(&request_id.to_le_bytes()); }
            Self::RevokeNotice { swarm_id, epoch, owner_sig } => { out.push(Self::REVOKE_NOTICE); out.extend_from_slice(swarm_id); out.extend_from_slice(&epoch.to_le_bytes()); out.extend_from_slice(owner_sig); }
            Self::Error { code } => { out.push(Self::ERROR); out.extend_from_slice(&code.to_le_bytes()); }
        }
        if out.len() > MAX_FRAME_SIZE { return Err(ProtocolError::FrameTooLarge); }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_SIZE { return Err(ProtocolError::Malformed); }
        let mut cursor = Cursor::new(bytes); let kind = cursor.u8()?;
        let message = match kind {
            Self::HELLO => { let capability = Capability::decode(cursor.bytes(MAX_CAPABILITY_BYTES)?)?; let challenge = cursor.array::<32>()?; let challenge_response = cursor.array::<64>()?; Self::Hello(Hello { capability, challenge, challenge_response }) }
            Self::BLOCK_BITMAP => { let object_id = cursor.array::<16>()?; let bitmap = cursor.bounded_bytes(MAX_BITMAP_BYTES)?; Self::BlockBitmap { object_id, bitmap } }
            Self::MANIFEST => { let object_id = cursor.array::<16>()?; let manifest_id = cursor.array::<32>()?; let nonce = cursor.array::<24>()?; let owner_signature = cursor.array::<64>()?; let bytes = cursor.bounded_bytes(MAX_MANIFEST_BYTES)?; Self::Manifest { object_id, manifest_id, nonce, owner_signature, bytes } }
            Self::REQUEST_BLOCKS => { let object_id = cursor.array::<16>()?; let count = cursor.u16()? as usize; if count > MAX_BLOCKS_PER_MESSAGE { return Err(ProtocolError::TooManyItems); } let block_ids = (0..count).map(|_| cursor.array::<32>()).collect::<Result<Vec<_>, _>>()?; Self::RequestBlocks { object_id, block_ids } }
            Self::BLOCK => { let block_id = cursor.array::<32>()?; let bytes = cursor.bounded_bytes(MAX_BLOCK_BYTES)?; Self::Block { block_id, bytes } }
            Self::HAVE => { let object_id = cursor.array::<16>()?; let count = cursor.u16()? as usize; if count > MAX_BLOCKS_PER_MESSAGE { return Err(ProtocolError::TooManyItems); } let block_ids = (0..count).map(|_| cursor.array::<32>()).collect::<Result<Vec<_>, _>>()?; Self::Have { object_id, block_ids } }
            Self::CANCEL => Self::Cancel { request_id: cursor.u64()? },
            Self::REVOKE_NOTICE => Self::RevokeNotice { swarm_id: cursor.array::<32>()?, epoch: cursor.u64()?, owner_sig: cursor.array::<64>()? },
            Self::ERROR => Self::Error { code: cursor.u16()? },
            _ => return Err(ProtocolError::Malformed),
        };
        cursor.finish()?; Ok(message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState { AwaitingHello, Ready, Closed }

pub struct Session {
    state: SessionState,
    capability: Option<Capability>,
}

impl Session {
    pub fn new() -> Self { Self { state: SessionState::AwaitingHello, capability: None } }
    pub fn state(&self) -> SessionState { self.state }

    pub fn receive(&mut self, message: Message, owner: &VerifyingKey, context: &CapabilityContext<'_>) -> Result<(), ProtocolError> {
        match (self.state, message) {
            (SessionState::AwaitingHello, Message::Hello(hello)) => {
                hello.capability.validate(owner, context)?;
                hello.verify_subject()?;
                self.capability = Some(hello.capability);
                self.state = SessionState::Ready;
                Ok(())
            }
            (SessionState::AwaitingHello, _) => Err(ProtocolError::InvalidState),
            (SessionState::Ready, Message::Hello(_)) => Err(ProtocolError::InvalidState),
            (SessionState::Ready, message) => {
                self.capability.as_ref().ok_or(ProtocolError::InvalidState)?.validate(owner, context)?;
                validate_message_scope(&message, owner, context)
            }
            (SessionState::Closed, _) => Err(ProtocolError::InvalidState),
        }
    }

    pub fn close(&mut self) { self.state = SessionState::Closed; }
}

impl Default for Session { fn default() -> Self { Self::new() } }

pub fn write_frame<W: Write>(writer: &mut W, message: &Message) -> Result<(), ProtocolError> {
    let bytes = message.encode()?; let length = u32::try_from(bytes.len()).map_err(|_| ProtocolError::FrameTooLarge)?; writer.write_all(&length.to_le_bytes())?; writer.write_all(&bytes)?; Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Message, ProtocolError> {
    let mut header = [0u8; 4]; reader.read_exact(&mut header)?; let length = u32::from_le_bytes(header) as usize; if length == 0 || length > MAX_FRAME_SIZE { return Err(ProtocolError::FrameTooLarge); } let mut bytes = vec![0u8; length]; reader.read_exact(&mut bytes)?; Message::decode(&bytes)
}

fn check_count(count: usize) -> Result<(), ProtocolError> { if count > MAX_BLOCKS_PER_MESSAGE { Err(ProtocolError::TooManyItems) } else { Ok(()) } }
fn validate_message_scope(message: &Message, owner: &VerifyingKey, context: &CapabilityContext<'_>) -> Result<(), ProtocolError> {
    if let Some(expected_object) = context.object_id {
        let object_id = match message {
            Message::BlockBitmap { object_id, .. } | Message::Manifest { object_id, .. } | Message::RequestBlocks { object_id, .. } | Message::Have { object_id, .. } => Some(object_id),
            _ => None,
        };
        if object_id.is_some_and(|value| value != expected_object) { return Err(ProtocolError::ScopeMismatch); }
    }
    if let Message::RevokeNotice { swarm_id, epoch, owner_sig } = message {
        if swarm_id != context.swarm_id || *epoch < context.revoked_epoch { return Err(ProtocolError::ScopeMismatch); }
        owner.verify(&revoke_bytes(swarm_id, *epoch), &Signature::from_bytes(owner_sig)).map_err(|_| ProtocolError::InvalidCapabilitySignature)?;
    }
    Ok(())
}
fn revoke_bytes(swarm_id: &[u8; 32], epoch: u64) -> Vec<u8> { let mut bytes = Vec::with_capacity(40); bytes.extend_from_slice(swarm_id); bytes.extend_from_slice(&epoch.to_le_bytes()); bytes }
fn put_u16(out: &mut Vec<u8>, value: usize) { out.extend_from_slice(&(value as u16).to_le_bytes()); }
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ProtocolError> { let length = u32::try_from(bytes.len()).map_err(|_| ProtocolError::FrameTooLarge)?; out.extend_from_slice(&length.to_le_bytes()); out.extend_from_slice(bytes); Ok(()) }

struct Cursor<'a> { bytes: &'a [u8], position: usize }

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, position: 0 } }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> { let end = self.position.checked_add(length).ok_or(ProtocolError::Malformed)?; let slice = self.bytes.get(self.position..end).ok_or(ProtocolError::Malformed)?; self.position = end; Ok(slice) }
    fn u8(&mut self) -> Result<u8, ProtocolError> { Ok(*self.take(1)?.first().ok_or(ProtocolError::Malformed)?) }
    fn u16(&mut self) -> Result<u16, ProtocolError> { Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| ProtocolError::Malformed)?)) }
    fn u32(&mut self) -> Result<u32, ProtocolError> { Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| ProtocolError::Malformed)?)) }
    fn u64(&mut self) -> Result<u64, ProtocolError> { Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| ProtocolError::Malformed)?)) }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> { self.take(N)?.try_into().map_err(|_| ProtocolError::Malformed) }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8], ProtocolError> { let length = self.u32()? as usize; if length > max { return Err(ProtocolError::FrameTooLarge); } self.take(length) }
    fn bounded_bytes(&mut self, max: usize) -> Result<Vec<u8>, ProtocolError> { Ok(self.bytes(max)?.to_vec()) }
    fn finish(&self) -> Result<(), ProtocolError> { if self.position == self.bytes.len() { Ok(()) } else { Err(ProtocolError::Malformed) } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn context<'a>(swarm: &'a [u8; 32], object: &'a [u8; 16], now: u64) -> CapabilityContext<'a> { CapabilityContext { swarm_id: swarm, object_id: Some(object), required_perm: permission::DOWNLOAD, revoked_epoch: 0, now } }

    #[test]
    fn signed_capability_and_hello_round_trip() {
        let owner = SigningKey::generate(&mut OsRng); let participant = SigningKey::generate(&mut OsRng); let swarm = [7u8; 32]; let object = [8u8; 16]; let capability = Capability::new(swarm, Some(object), participant.verifying_key().to_bytes(), permission::DOWNLOAD, 10, 20, 1).sign(&owner); let hello = Message::Hello(Hello::new(capability.clone(), [9u8; 32], &participant)); let encoded = hello.encode().unwrap(); let decoded = Message::decode(&encoded).unwrap(); assert_eq!(decoded, hello); let mut session = Session::new(); session.receive(decoded, &owner.verifying_key(), &context(&swarm, &object, 15)).unwrap(); assert_eq!(session.state(), SessionState::Ready); let wrong_object = [6u8; 16]; assert_eq!(session.receive(Message::RequestBlocks { object_id: wrong_object, block_ids: vec![] }, &owner.verifying_key(), &context(&swarm, &object, 15)), Err(ProtocolError::ScopeMismatch)); }

    #[test]
    fn ready_session_revalidates_capability() {
        let owner = SigningKey::generate(&mut OsRng);
        let participant = SigningKey::generate(&mut OsRng);
        let swarm = [7u8; 32];
        let object = [8u8; 16];
        let capability = Capability::new(swarm, Some(object), participant.verifying_key().to_bytes(), permission::DOWNLOAD, 10, 20, 1).sign(&owner);
        let mut session = Session::new();
        session.receive(Message::Hello(Hello::new(capability, [9u8; 32], &participant)), &owner.verifying_key(), &context(&swarm, &object, 15)).unwrap();
        let mut revoked = context(&swarm, &object, 15);
        revoked.revoked_epoch = 2;
        assert_eq!(session.receive(Message::Cancel { request_id: 0 }, &owner.verifying_key(), &revoked), Err(ProtocolError::CapabilityDenied));
        assert_eq!(session.receive(Message::Cancel { request_id: 0 }, &owner.verifying_key(), &context(&swarm, &object, 20)), Err(ProtocolError::CapabilityDenied));
    }

    #[test]
    fn no_data_before_capability_validation() {
        let owner = SigningKey::generate(&mut OsRng); let swarm = [1u8; 32]; let object = [2u8; 16]; let mut session = Session::new(); let message = Message::Block { block_id: [3u8; 32], bytes: vec![1, 2, 3] }; assert_eq!(session.receive(message, &owner.verifying_key(), &context(&swarm, &object, 15)), Err(ProtocolError::InvalidState)); }

    #[test]
    fn expired_revoked_and_wrong_scope_capabilities_fail() {
        let owner = SigningKey::generate(&mut OsRng); let participant = SigningKey::generate(&mut OsRng); let swarm = [1u8; 32]; let object = [2u8; 16]; let capability = Capability::new(swarm, Some(object), participant.verifying_key().to_bytes(), permission::DOWNLOAD, 10, 20, 1).sign(&owner); assert_eq!(capability.validate(&owner.verifying_key(), &context(&swarm, &object, 20)), Err(ProtocolError::CapabilityDenied)); let mut revoked = context(&swarm, &object, 15); revoked.revoked_epoch = 2; assert_eq!(capability.validate(&owner.verifying_key(), &revoked), Err(ProtocolError::CapabilityDenied)); let other = [4u8; 16]; assert_eq!(capability.validate(&owner.verifying_key(), &context(&swarm, &other, 15)), Err(ProtocolError::ScopeMismatch)); }

    #[test]
    fn bounded_frames_reject_large_allocations() {
        let mut bytes = Vec::new(); bytes.extend_from_slice(&(u32::MAX).to_le_bytes()); assert_eq!(read_frame(&mut bytes.as_slice()), Err(ProtocolError::FrameTooLarge)); let request = Message::RequestBlocks { object_id: [0; 16], block_ids: vec![[0; 32]; MAX_BLOCKS_PER_MESSAGE + 1] }; assert_eq!(request.encode(), Err(ProtocolError::TooManyItems)); }

    #[test]
    fn frame_io_round_trip() {
        let message = Message::Cancel { request_id: 42 }; let mut bytes = Vec::new(); write_frame(&mut bytes, &message).unwrap(); assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), message); }

    #[test]
    fn encrypted_manifest_frame_round_trips_and_is_bounded() {
        let message = Message::Manifest { object_id: [1; 16], manifest_id: [2; 32], nonce: [4; 24], owner_signature: [5; 64], bytes: vec![3; 128] };
        assert_eq!(Message::decode(&message.encode().unwrap()).unwrap(), message);
        assert_eq!(Message::Manifest { object_id: [0; 16], manifest_id: [0; 32], nonce: [0; 24], owner_signature: [0; 64], bytes: vec![0; MAX_MANIFEST_BYTES + 1] }.encode(), Err(ProtocolError::FrameTooLarge));
    }

    #[test]
    fn signed_revoke_notice_is_validated() {
        let owner = SigningKey::generate(&mut OsRng);
        let participant = SigningKey::generate(&mut OsRng);
        let swarm = [5u8; 32];
        let object = [0u8; 16];
        let capability = Capability::new(swarm, Some(object), participant.verifying_key().to_bytes(), permission::DOWNLOAD, 0, 100, 0).sign(&owner);
        let mut session = Session::new();
        session.receive(Message::Hello(Hello::new(capability, [9u8; 32], &participant)), &owner.verifying_key(), &context(&swarm, &object, 1)).unwrap();
        let message = Message::revoke_notice(swarm, 2, &owner);
        session.receive(message, &owner.verifying_key(), &context(&swarm, &object, 1)).unwrap();
    }
}
