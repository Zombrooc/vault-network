//! Invitation creation and opening.
//!
//! The outer envelope contains only HPKE encapsulation material, ciphertext and
//! an owner signature. Content keys, capabilities and participation secrets are
//! inside the HPKE plaintext and never cross the frontend boundary.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hpke::{
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{X25519HkdfSha256, Kem as KemTrait},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use thiserror::Error;
use vault_identity::{Identity, ParticipationKey};
use vault_protocol::{manifest_signing_bytes, Capability};
use zeroize::{Zeroize, Zeroizing};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

const VERSION: u8 = 1;
const INFO: &[u8] = b"vault/v1/invitation";
const AAD: &[u8] = b"vault/v1/invitation-payload";
const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024;
const MAX_RELAY_HINTS: usize = 8;
const MAX_RELAY_HINT_BYTES: usize = 256;

#[derive(Debug, Error)]
pub enum SharingError {
    #[error("invitation is malformed")]
    Malformed,
    #[error("invitation is too large")]
    TooLarge,
    #[error("HPKE operation failed")]
    Hpke,
    #[error("owner signature is invalid")]
    InvalidOwnerSignature,
    #[error("capability does not match the invitation")]
    CapabilityMismatch,
    #[error("invitation protocol error: {0}")]
    Protocol(#[from] vault_protocol::ProtocolError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationPayload {
    pub object_id: [u8; 16],
    pub manifest_id: [u8; 32],
    pub manifest_signature: [u8; 64],
    pub swarm_id: [u8; 32],
    pub owner_pubkey: [u8; 32],
    pub cek: [u8; 32],
    pub participation_secret: [u8; 32],
    pub capability: Capability,
    pub relay_hints: Vec<String>,
    pub permissions: u32,
}

impl Drop for InvitationPayload {
    fn drop(&mut self) { self.cek.zeroize(); self.participation_secret.zeroize(); }
}

impl InvitationPayload {
    pub fn validate(&self) -> Result<(), SharingError> {
        let participant = ParticipationKey::from_secret_bytes(self.participation_secret);
        if self.capability.subject_pubkey != participant.public_key() || self.capability.swarm_id != self.swarm_id || self.capability.object_id != Some(self.object_id) || self.capability.perms != self.permissions {
            return Err(SharingError::CapabilityMismatch);
        }
        let owner = VerifyingKey::from_bytes(&self.owner_pubkey).map_err(|_| SharingError::InvalidOwnerSignature)?;
        self.capability.verify_owner(&owner).map_err(|_| SharingError::InvalidOwnerSignature)?;
        owner.verify(&manifest_signing_bytes(&self.manifest_id, &self.swarm_id, &self.object_id), &Signature::from_bytes(&self.manifest_signature)).map_err(|_| SharingError::InvalidOwnerSignature)
    }

    fn encode(&self) -> Result<Vec<u8>, SharingError> {
        self.validate()?;
        if self.relay_hints.len() > MAX_RELAY_HINTS || self.relay_hints.iter().any(|hint| hint.is_empty() || hint.len() > MAX_RELAY_HINT_BYTES) { return Err(SharingError::Malformed); }
        let capability = self.capability.encode(); let mut out = Vec::new(); out.extend_from_slice(&self.object_id); out.extend_from_slice(&self.manifest_id); out.extend_from_slice(&self.manifest_signature); out.extend_from_slice(&self.swarm_id); out.extend_from_slice(&self.owner_pubkey); out.extend_from_slice(&self.cek); out.extend_from_slice(&self.participation_secret); put_bytes(&mut out, &capability)?; put_u16(&mut out, self.relay_hints.len()); for hint in &self.relay_hints { put_bytes(&mut out, hint.as_bytes())?; } out.extend_from_slice(&self.permissions.to_le_bytes()); Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, SharingError> {
        let mut cursor = Cursor::new(bytes); let object_id = cursor.array::<16>()?; let manifest_id = cursor.array::<32>()?; let manifest_signature = cursor.array::<64>()?; let swarm_id = cursor.array::<32>()?; let owner_pubkey = cursor.array::<32>()?; let cek = cursor.array::<32>()?; let participation_secret = cursor.array::<32>()?; let capability = Capability::decode(cursor.bytes(512)?)?; let hint_count = cursor.u16()? as usize; if hint_count > MAX_RELAY_HINTS { return Err(SharingError::TooLarge); } let mut relay_hints = Vec::with_capacity(hint_count); for _ in 0..hint_count { let hint = String::from_utf8(cursor.bytes(MAX_RELAY_HINT_BYTES)?.to_vec()).map_err(|_| SharingError::Malformed)?; if hint.is_empty() { return Err(SharingError::Malformed); } relay_hints.push(hint); } let permissions = cursor.u32()?; cursor.finish()?; let payload = Self { object_id, manifest_id, manifest_signature, swarm_id, owner_pubkey, cek, participation_secret, capability, relay_hints, permissions }; payload.validate()?; Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub owner_sig: [u8; 64],
}

impl Invitation {
    pub fn seal(payload: &InvitationPayload, recipient: &[u8; 32], owner: &ed25519_dalek::SigningKey) -> Result<Self, SharingError> {
        if owner.verifying_key().to_bytes() != payload.owner_pubkey { return Err(SharingError::InvalidOwnerSignature); }
        let mut plaintext = payload.encode()?;
        let recipient_key = <Kem as KemTrait>::PublicKey::from_bytes(recipient).map_err(|_| SharingError::Hpke)?;
        let (encapsulated_key, mut sender) = hpke::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &recipient_key, INFO).map_err(|_| SharingError::Hpke)?;
        let result = sender.seal(&plaintext, AAD).map_err(|_| SharingError::Hpke);
        plaintext.zeroize();
        let ciphertext = result?;
        if ciphertext.len() > MAX_CIPHERTEXT { return Err(SharingError::TooLarge); }
        let invitation = Self { encapsulated_key: encapsulated_key.to_bytes().to_vec(), ciphertext, owner_sig: [0u8; 64] };
        let owner_sig = owner.sign(&invitation.unsigned_bytes()).to_bytes();
        Ok(Self { owner_sig, ..invitation })
    }

    pub fn open(&self, recipient: &Identity) -> Result<InvitationPayload, SharingError> {
        if self.encapsulated_key.len() > 128 || self.ciphertext.len() > MAX_CIPHERTEXT { return Err(SharingError::TooLarge); }
        let secret = recipient.hpke_secret_bytes(); let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&*secret).map_err(|_| SharingError::Hpke)?; let encapsulated_key = <Kem as KemTrait>::EncappedKey::from_bytes(&self.encapsulated_key).map_err(|_| SharingError::Hpke)?; let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &private_key, &encapsulated_key, INFO).map_err(|_| SharingError::Hpke)?; let plaintext = Zeroizing::new(receiver.open(&self.ciphertext, AAD).map_err(|_| SharingError::Hpke)?); let payload = InvitationPayload::decode(plaintext.as_slice())?; let owner = VerifyingKey::from_bytes(&payload.owner_pubkey).map_err(|_| SharingError::InvalidOwnerSignature)?; owner.verify(&self.unsigned_bytes(), &Signature::from_bytes(&self.owner_sig)).map_err(|_| SharingError::InvalidOwnerSignature)?; Ok(payload)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SharingError> {
        if self.encapsulated_key.len() > 128 || self.ciphertext.len() > MAX_CIPHERTEXT { return Err(SharingError::TooLarge); }
        let mut out = self.unsigned_bytes(); out.extend_from_slice(&self.owner_sig); Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SharingError> {
        let mut cursor = Cursor::new(bytes); if cursor.u8()? != VERSION { return Err(SharingError::Malformed); } let encap = cursor.bytes(128)?.to_vec(); if encap.is_empty() { return Err(SharingError::Malformed); } let ciphertext = cursor.bytes(MAX_CIPHERTEXT)?.to_vec(); let owner_sig = cursor.array::<64>()?; cursor.finish()?; Ok(Self { encapsulated_key: encap, ciphertext, owner_sig })
    }

    fn unsigned_bytes(&self) -> Vec<u8> { let mut out = vec![VERSION]; let _ = put_bytes(&mut out, &self.encapsulated_key); let _ = put_bytes(&mut out, &self.ciphertext); out }
}

struct Cursor<'a> { bytes: &'a [u8], position: usize }

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, position: 0 } }
    fn take(&mut self, size: usize) -> Result<&'a [u8], SharingError> { let end = self.position.checked_add(size).ok_or(SharingError::Malformed)?; let result = self.bytes.get(self.position..end).ok_or(SharingError::Malformed)?; self.position = end; Ok(result) }
    fn u8(&mut self) -> Result<u8, SharingError> { Ok(*self.take(1)?.first().ok_or(SharingError::Malformed)?) }
    fn u16(&mut self) -> Result<u16, SharingError> { Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| SharingError::Malformed)?)) }
    fn u32(&mut self) -> Result<u32, SharingError> { Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| SharingError::Malformed)?)) }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], SharingError> { self.take(N)?.try_into().map_err(|_| SharingError::Malformed) }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8], SharingError> { let length = self.u32()? as usize; if length > max { return Err(SharingError::TooLarge); } self.take(length) }
    fn finish(&self) -> Result<(), SharingError> { if self.position == self.bytes.len() { Ok(()) } else { Err(SharingError::Malformed) } }
}

fn put_u16(out: &mut Vec<u8>, value: usize) { out.extend_from_slice(&(value as u16).to_le_bytes()); }
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SharingError> { let length = u32::try_from(bytes.len()).map_err(|_| SharingError::TooLarge)?; out.extend_from_slice(&length.to_le_bytes()); out.extend_from_slice(bytes); Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    use vault_protocol::permission;

    #[test]
    fn invitation_round_trip_is_recipient_bound() {
        let owner = Identity::generate(); let recipient = Identity::generate(); let other = Identity::generate(); let participant = ParticipationKey::generate(); let swarm = [1u8; 32]; let object = [2u8; 16]; let manifest_id = [3u8; 32]; let capability = Capability::new(swarm, Some(object), participant.public_key(), permission::DOWNLOAD, 1, 100, 0).sign(owner.signing_key()); let payload = InvitationPayload { object_id: object, manifest_id, manifest_signature: owner.sign(&manifest_signing_bytes(&manifest_id, &swarm, &object)), swarm_id: swarm, owner_pubkey: owner.public().signing_public, cek: [4u8; 32], participation_secret: *participant.secret_bytes(), capability, relay_hints: vec!["/dns4/relay.example/tcp/443".to_owned()], permissions: permission::DOWNLOAD }; let invitation = Invitation::seal(&payload, &recipient.public().hpke_public, owner.signing_key()).unwrap(); let encoded = invitation.encode().unwrap(); let decoded = Invitation::decode(&encoded).unwrap(); assert_eq!(decoded.open(&recipient).unwrap(), payload); assert!(matches!(decoded.open(&other), Err(SharingError::Hpke))); }

    #[test]
    fn malformed_or_tampered_invitation_fails() {
        let owner = Identity::generate(); let recipient = Identity::generate(); let participant = ParticipationKey::generate(); let swarm = [1u8; 32]; let object = [2u8; 16]; let manifest_id = [3u8; 32]; let capability = Capability::new(swarm, Some(object), participant.public_key(), permission::DOWNLOAD, 1, 100, 0).sign(owner.signing_key()); let payload = InvitationPayload { object_id: object, manifest_id, manifest_signature: owner.sign(&manifest_signing_bytes(&manifest_id, &swarm, &object)), swarm_id: swarm, owner_pubkey: owner.public().signing_public, cek: [4u8; 32], participation_secret: *participant.secret_bytes(), capability, relay_hints: vec![], permissions: permission::DOWNLOAD }; let mut invitation = Invitation::seal(&payload, &recipient.public().hpke_public, owner.signing_key()).unwrap(); invitation.ciphertext[0] ^= 1; assert!(matches!(invitation.open(&recipient), Err(SharingError::Hpke))); let encoded = invitation.encode().unwrap(); assert!(Invitation::decode(&encoded).is_ok()); }
}
