//! Identity material kept behind the Rust boundary.
//!
//! Identity keys are per-container. Participation keys are deliberately
//! separate per swarm, so network peer identifiers are not linkable across
//! sharing scopes.

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use std::io::{Cursor, Read};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

const CARD_VERSION: u8 = 1;
const MAX_CONTACT_NAME_BYTES: usize = 128;
const KEY_BYTES: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("contact card is invalid")]
    InvalidCard,
    #[error("contact name is invalid")]
    InvalidName,
    #[error("signature is invalid")]
    InvalidSignature,
    #[error("input is truncated")]
    Truncated,
}

pub struct Identity {
    signing_key: SigningKey,
    hpke_secret: StaticSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPublic {
    pub signing_public: [u8; KEY_BYTES],
    pub hpke_public: [u8; KEY_BYTES],
}

impl Identity {
    pub fn generate() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng), hpke_secret: StaticSecret::random_from_rng(OsRng) }
    }

    pub fn from_secret_bytes(signing_secret: [u8; KEY_BYTES], hpke_secret: [u8; KEY_BYTES]) -> Self {
        Self { signing_key: SigningKey::from_bytes(&signing_secret), hpke_secret: StaticSecret::from(hpke_secret) }
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic { signing_public: self.signing_key.verifying_key().to_bytes(), hpke_public: X25519PublicKey::from(&self.hpke_secret).to_bytes() }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] { self.signing_key.sign(message).to_bytes() }

    pub fn signing_key(&self) -> &SigningKey { &self.signing_key }

    pub fn signing_secret_bytes(&self) -> Zeroizing<[u8; KEY_BYTES]> { Zeroizing::new(self.signing_key.to_bytes()) }

    pub fn hpke_secret_bytes(&self) -> Zeroizing<[u8; KEY_BYTES]> { Zeroizing::new(*self.hpke_secret.as_bytes()) }

    pub fn agree(&self, peer: &IdentityPublic) -> Zeroizing<[u8; KEY_BYTES]> {
        let shared = self.hpke_secret.diffie_hellman(&X25519PublicKey::from(peer.hpke_public));
        Zeroizing::new(*shared.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCard {
    pub name: String,
    pub public: IdentityPublic,
}

impl ContactCard {
    pub fn new(name: impl Into<String>, public: IdentityPublic) -> Result<Self, IdentityError> {
        let name = name.into(); validate_name(&name)?; Ok(Self { name, public })
    }

    pub fn fingerprint(&self) -> [u8; 8] {
        let mut hasher = Hasher::new(); hasher.update(b"vault/v1/contact-fingerprint"); hasher.update(&self.public.signing_public); hasher.update(&self.public.hpke_public); let hash = hasher.finalize(); hash.as_bytes()[..8].try_into().expect("fixed fingerprint length")
    }

    pub fn fingerprint_hex(&self) -> String { self.fingerprint().iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":") }

    pub fn encode(&self) -> Vec<u8> {
        let name = self.name.as_bytes(); let mut bytes = Vec::with_capacity(1 + 2 + name.len() + KEY_BYTES * 2); bytes.push(CARD_VERSION); bytes.extend_from_slice(&(name.len() as u16).to_le_bytes()); bytes.extend_from_slice(name); bytes.extend_from_slice(&self.public.signing_public); bytes.extend_from_slice(&self.public.hpke_public); bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut cursor = Cursor::new(bytes); let version = read_u8(&mut cursor)?; if version != CARD_VERSION { return Err(IdentityError::InvalidCard); } let name_len = read_u16(&mut cursor)? as usize; if name_len == 0 || name_len > MAX_CONTACT_NAME_BYTES { return Err(IdentityError::InvalidName); } let mut name_bytes = vec![0u8; name_len]; cursor.read_exact(&mut name_bytes).map_err(|_| IdentityError::Truncated)?; let name = String::from_utf8(name_bytes).map_err(|_| IdentityError::InvalidName)?; let mut signing_public = [0u8; KEY_BYTES]; cursor.read_exact(&mut signing_public).map_err(|_| IdentityError::Truncated)?; let mut hpke_public = [0u8; KEY_BYTES]; cursor.read_exact(&mut hpke_public).map_err(|_| IdentityError::Truncated)?; if cursor.position() != bytes.len() as u64 { return Err(IdentityError::InvalidCard); } Self::new(name, IdentityPublic { signing_public, hpke_public })
    }
}

pub struct ParticipationKey(SigningKey);

impl ParticipationKey {
    pub fn generate() -> Self { Self(SigningKey::generate(&mut OsRng)) }
    pub fn from_secret_bytes(bytes: [u8; KEY_BYTES]) -> Self { Self(SigningKey::from_bytes(&bytes)) }
    pub fn secret_bytes(&self) -> Zeroizing<[u8; KEY_BYTES]> { Zeroizing::new(self.0.to_bytes()) }
    pub fn public_key(&self) -> [u8; KEY_BYTES] { self.0.verifying_key().to_bytes() }
    pub fn sign_challenge(&self, challenge: &[u8; 32]) -> [u8; 64] { self.0.sign(challenge).to_bytes() }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] { self.0.sign(message).to_bytes() }
    pub fn peer_id(&self) -> [u8; 32] { let mut hasher = Hasher::new(); hasher.update(b"vault/v1/participation-peer-id"); hasher.update(&self.public_key()); *hasher.finalize().as_bytes() }
    pub fn verify_challenge(&self, challenge: &[u8; 32], signature: &[u8; 64]) -> Result<(), IdentityError> { let signature = Signature::from_bytes(signature); self.0.verifying_key().verify_strict(challenge, &signature).map_err(|_| IdentityError::InvalidSignature) }
}

fn validate_name(name: &str) -> Result<(), IdentityError> { if name.is_empty() || name.len() > MAX_CONTACT_NAME_BYTES || name.contains('\0') { Err(IdentityError::InvalidName) } else { Ok(()) } }
fn read_u8<R: Read>(reader: &mut R) -> Result<u8, IdentityError> { let mut bytes = [0u8; 1]; reader.read_exact(&mut bytes).map_err(|_| IdentityError::Truncated)?; Ok(bytes[0]) }
fn read_u16<R: Read>(reader: &mut R) -> Result<u16, IdentityError> { let mut bytes = [0u8; 2]; reader.read_exact(&mut bytes).map_err(|_| IdentityError::Truncated)?; Ok(u16::from_le_bytes(bytes)) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_card_round_trips_and_has_stable_fingerprint() {
        let identity = Identity::generate(); let card = ContactCard::new("Marina Alves", identity.public()).unwrap(); let decoded = ContactCard::decode(&card.encode()).unwrap(); assert_eq!(decoded, card); assert_eq!(decoded.fingerprint(), card.fingerprint()); assert_eq!(decoded.fingerprint_hex().len(), 23);
    }

    #[test]
    fn identity_agreement_is_symmetric() {
        let alice = Identity::generate(); let bob = Identity::generate(); assert_eq!(alice.agree(&bob.public()), bob.agree(&alice.public()));
    }

    #[test]
    fn participation_keys_are_not_reused_between_swarms() {
        let first = ParticipationKey::generate(); let second = ParticipationKey::generate(); assert_ne!(first.public_key(), second.public_key()); assert_ne!(first.peer_id(), second.peer_id()); let challenge = [4u8; 32]; let signature = first.sign_challenge(&challenge); assert!(first.verify_challenge(&challenge, &signature).is_ok());
    }

    #[test]
    fn malformed_contact_names_are_rejected() {
        assert_eq!(ContactCard::new("", Identity::generate().public()), Err(IdentityError::InvalidName)); assert_eq!(ContactCard::new("a\0b", Identity::generate().public()), Err(IdentityError::InvalidName));
    }
}
