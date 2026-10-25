//! The local M1 storage core.
//!
//! The public API deliberately takes readers and writers so the desktop shell can
//! keep file I/O out of the frontend and stream large imports.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{AeadInPlace, KeyInit}, XChaCha20Poly1305, XNonce};
use fs2::FileExt;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
use vault_identity::Identity;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"VLTN\0\0\0\x01";
const BACKUP_MAGIC: &[u8; 8] = b"VLTBKP\0\x01";
const FORMAT_VERSION: u16 = 1;
const HEADER_NAME: &str = "header.bin";
const IDENTITY_NAME: &str = "identity.bin";
const LOCK_NAME: &str = "lock";
const INDEX_DIR: &str = "index/objects";
const FOLDER_INDEX_NAME: &str = "index/folders.bin";
const REVOCATION_INDEX_NAME: &str = "index/revocations.bin";
const TRANSFER_DIR: &str = "index/transfers";
const ROTATION_JOURNAL_NAME: &str = "rotation.bin";
const COMPACTION_JOURNAL_NAME: &str = "compaction.bin";
const SEGMENT_DIR: &str = "seg";
const SEGMENT_NAME: &str = "00000001.seg";
const BLOCK_AAD: &[u8] = b"vault/v1/block";
const MANIFEST_AAD: &[u8] = b"vault/v1/manifest";
const INDEX_AAD: &[u8] = b"vault/v1/index-record";
const FOLDER_AAD: &[u8] = b"vault/v1/folder-index";
const REVOCATION_AAD: &[u8] = b"vault/v1/revocation-index";
const TRANSFER_AAD: &[u8] = b"vault/v1/transfer-checkpoint";
const ROTATION_MAGIC: &[u8; 8] = b"VLTROT\0\x01";
const COMPACTION_MAGIC: &[u8; 8] = b"VLTGC\0\0\x01";
const IDENTITY_AAD: &[u8] = b"vault/v1/identity";
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;
const SALT_LENGTH: usize = 16;
const NONCE_PREFIX_LENGTH: usize = 15;
const TAG_LENGTH: usize = 16;
const DEFAULT_BLOCK_SIZE: usize = 1024 * 1024;
const MIN_BLOCK_SIZE: usize = 256 * 1024;
const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;
const PAD_UNIT: usize = 64 * 1024;
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_TIME: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const ARGON_OUTPUT_LENGTH: usize = KEY_LENGTH;
const MAX_KEYFILE_BYTES: usize = 1024 * 1024;
const MAX_BACKUP_COMPONENT_BYTES: usize = 64 * 1024;
const SLOT_PASSWORD: u8 = 1;
const SLOT_RECOVERY: u8 = 2;
const SLOT_COUNT: usize = 2;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ROTATION_PREPARED: u8 = 1;
const ROTATION_INDEX_SWAPPED: u8 = 2;
const ROTATION_IDENTITY_SWAPPED: u8 = 3;
const ROTATION_HEADER_SWAPPED: u8 = 4;
const COMPACTION_PREPARED: u8 = 1;
const COMPACTION_SEGMENT_SWAPPED: u8 = 2;
const COMPACTION_INDEX_SWAPPED: u8 = 3;
const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
const AUTH_BACKOFF_BASE_MS: u64 = 250;
const AUTH_BACKOFF_MAX_MS: u64 = 4_000;

// shortcut: throttling is process-local; persist attempts only with a separate authenticated rate-limit store.
static AUTH_FAILURES: OnceLock<Mutex<HashMap<PathBuf, (Instant, u32)>>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("container already exists")]
    AlreadyExists,
    #[error("container does not exist")]
    NotFound,
    #[error("container format is invalid")]
    InvalidFormat,
    #[error("container format version is unsupported")]
    UnsupportedVersion,
    #[error("password or recovery key is incorrect")]
    UnlockFailed,
    #[error("container is already open by another process")]
    AlreadyOpen,
    #[error("container integrity check failed")]
    Integrity,
    #[error("invalid recovery key")]
    InvalidRecoveryKey,
    #[error("invalid object identifier")]
    InvalidObjectId,
    #[error("plaintext length does not match the supplied reader")]
    LengthMismatch,
    #[error("object is larger than the v1 authenticated length field")]
    FileTooLarge,
    #[error("requested block size is outside the v1 range")]
    InvalidBlockSize,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("cryptographic operation failed")]
    Crypto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectId([u8; 16]);

impl ObjectId {
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self { Self(bytes) }

    pub fn as_bytes(&self) -> &[u8; 16] { &self.0 }
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub id: ObjectId,
    pub name: String,
    pub plaintext_len: u64,
    pub block_count: usize,
}

#[derive(Debug, Clone)]
pub struct EncryptedBlock {
    pub id: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptedObject {
    pub manifest_id: [u8; 32],
    pub manifest_nonce: [u8; 24],
    pub manifest_ciphertext: Vec<u8>,
    pub blocks: Vec<EncryptedBlock>,
}

#[derive(Debug, Clone)]
pub struct TransferCheckpoint {
    pub cek: [u8; 32],
    pub manifest_id: [u8; 32],
    pub manifest_nonce: [u8; 24],
    pub manifest_ciphertext: Vec<u8>,
    pub blocks: Vec<EncryptedBlock>,
}

impl Drop for TransferCheckpoint {
    fn drop(&mut self) {
        self.cek.zeroize();
        for block in &mut self.blocks { block.bytes.zeroize(); }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedManifest {
    pub name: String,
    pub plaintext_len: u64,
    pub block_size: u32,
    pub nonce_prefix: [u8; 15],
    pub block_ids: Vec<[u8; 32]>,
}

#[derive(Debug)]
pub struct ObjectShareMaterial {
    pub cek: [u8; 32],
    pub manifest_id: [u8; 32],
}

impl Drop for ObjectShareMaterial {
    fn drop(&mut self) { self.cek.zeroize(); }
}

#[derive(Debug, Clone, Copy)]
struct KdfParams {
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { memory_kib: ARGON_MEMORY_KIB, time_cost: ARGON_TIME, parallelism: ARGON_PARALLELISM }
    }
}

impl KdfParams {
    fn validate(self) -> Result<(), VaultError> {
        if self.memory_kib < ARGON_MEMORY_KIB || self.time_cost < ARGON_TIME || self.parallelism != ARGON_PARALLELISM {
            return Err(VaultError::InvalidFormat);
        }
        Ok(())
    }

    fn derive(&self, password: &[u8], salt: &[u8; SALT_LENGTH]) -> Result<Zeroizing<[u8; KEY_LENGTH]>, VaultError> {
        self.validate()?;
        let params = Params::new(self.memory_kib, self.time_cost, self.parallelism, Some(ARGON_OUTPUT_LENGTH)).map_err(|_| VaultError::Crypto)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
        argon.hash_password_into(password, salt, key.as_mut()).map_err(|_| VaultError::Crypto)?;
        Ok(key)
    }
}

#[derive(Debug, Clone)]
struct KeySlot {
    kind: u8,
    nonce: [u8; NONCE_LENGTH],
    wrapped_cmk: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Header {
    version: u16,
    block_size: u32,
    kdf: KdfParams,
    salt: [u8; SALT_LENGTH],
    keyfile_required: bool,
    slots: Vec<KeySlot>,
}

#[derive(Debug)]
struct RotationJournal {
    phase: u8,
    old_header: Vec<u8>,
    new_header: Vec<u8>,
}

impl Header {
    fn new_with_unlock_key(cmk: &[u8; KEY_LENGTH], unlock_key: &[u8], keyfile_required: bool) -> Result<(Self, String), VaultError> {
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        let kdf = KdfParams::default();
        let mut recovery_bytes = [0u8; KEY_LENGTH];
        OsRng.fill_bytes(&mut recovery_bytes);
        let recovery_key = encode_recovery_key(&recovery_bytes);
        let password_slot = KeySlot::wrap(SLOT_PASSWORD, unlock_key, cmk, kdf, &salt)?;
        let recovery_slot = KeySlot::wrap(SLOT_RECOVERY, &recovery_bytes, cmk, kdf, &salt)?;
        recovery_bytes.zeroize();
        Ok((Self { version: FORMAT_VERSION, block_size: DEFAULT_BLOCK_SIZE as u32, kdf, salt, keyfile_required, slots: vec![password_slot, recovery_slot] }, recovery_key))
    }

    fn encode(&self) -> Result<Vec<u8>, VaultError> {
        if self.slots.len() != SLOT_COUNT || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&(self.block_size as usize)) {
            return Err(VaultError::InvalidFormat);
        }
        let mut out = Vec::with_capacity(8 + 2 + 4 + 12 + SALT_LENGTH + 1 + SLOT_COUNT * (1 + NONCE_LENGTH + KEY_LENGTH + TAG_LENGTH));
        out.extend_from_slice(MAGIC);
        put_u16(&mut out, self.version);
        put_u32(&mut out, self.block_size);
        put_u32(&mut out, self.kdf.memory_kib);
        put_u32(&mut out, self.kdf.time_cost);
        put_u32(&mut out, self.kdf.parallelism);
        out.extend_from_slice(&self.salt);
        out.push(self.slots.len() as u8);
        for slot in &self.slots {
            if slot.wrapped_cmk.len() != KEY_LENGTH + TAG_LENGTH { return Err(VaultError::InvalidFormat); }
            out.push(slot.kind);
            out.extend_from_slice(&slot.nonce);
            out.extend_from_slice(&slot.wrapped_cmk);
        }
        out.push(u8::from(self.keyfile_required));
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        let mut cursor = Cursor::new(bytes);
        let mut magic = [0u8; 8]; cursor.read_exact(&mut magic)?;
        if &magic != MAGIC { return Err(VaultError::InvalidFormat); }
        let version = read_u16(&mut cursor)?;
        if version != FORMAT_VERSION { return Err(VaultError::UnsupportedVersion); }
        let block_size = read_u32(&mut cursor)?;
        if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&(block_size as usize)) { return Err(VaultError::InvalidBlockSize); }
        let kdf = KdfParams { memory_kib: read_u32(&mut cursor)?, time_cost: read_u32(&mut cursor)?, parallelism: read_u32(&mut cursor)? };
        kdf.validate()?;
        let mut salt = [0u8; SALT_LENGTH]; cursor.read_exact(&mut salt)?;
        let slot_count = read_u8(&mut cursor)? as usize;
        if slot_count != SLOT_COUNT { return Err(VaultError::InvalidFormat); }
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let kind = read_u8(&mut cursor)?;
            if kind != SLOT_PASSWORD && kind != SLOT_RECOVERY { return Err(VaultError::InvalidFormat); }
            let mut nonce = [0u8; NONCE_LENGTH]; cursor.read_exact(&mut nonce)?;
            let mut wrapped_cmk = vec![0u8; KEY_LENGTH + TAG_LENGTH]; cursor.read_exact(&mut wrapped_cmk)?;
            slots.push(KeySlot { kind, nonce, wrapped_cmk });
        }
        if slots.iter().filter(|slot| slot.kind == SLOT_PASSWORD).count() != 1 || slots.iter().filter(|slot| slot.kind == SLOT_RECOVERY).count() != 1 {
            return Err(VaultError::InvalidFormat);
        }
        let keyfile_required = if cursor.position() == bytes.len() as u64 {
            false
        } else {
            match read_u8(&mut cursor)? { 0 => false, 1 => true, _ => return Err(VaultError::InvalidFormat) }
        };
        if cursor.position() != bytes.len() as u64 { return Err(VaultError::InvalidFormat); }
        Ok(Self { version, block_size, kdf, salt, keyfile_required, slots })
    }

    fn slot(&self, kind: u8) -> Option<&KeySlot> { self.slots.iter().find(|slot| slot.kind == kind) }
}

impl KeySlot {
    fn wrap(kind: u8, unlock_key: &[u8], cmk: &[u8; KEY_LENGTH], kdf: KdfParams, salt: &[u8; SALT_LENGTH]) -> Result<Self, VaultError> {
        let key = if kind == SLOT_RECOVERY {
            let bytes: [u8; KEY_LENGTH] = unlock_key.try_into().map_err(|_| VaultError::Crypto)?;
            Zeroizing::new(bytes)
        } else { kdf.derive(unlock_key, salt)? };
        let mut nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut nonce);
        let mut payload = cmk.to_vec();
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
        cipher.encrypt_in_place(XNonce::from_slice(&nonce), &slot_aad(kind, kdf, salt), &mut payload).map_err(|_| VaultError::Crypto)?;
        Ok(Self { kind, nonce, wrapped_cmk: payload })
    }

    fn unwrap(&self, unlock_key: &[u8], kdf: KdfParams, salt: &[u8; SALT_LENGTH]) -> Result<Zeroizing<[u8; KEY_LENGTH]>, VaultError> {
        let key = if self.kind == SLOT_RECOVERY {
            let bytes: [u8; KEY_LENGTH] = unlock_key.try_into().map_err(|_| VaultError::UnlockFailed)?;
            Zeroizing::new(bytes)
        } else { kdf.derive(unlock_key, salt).map_err(|_| VaultError::UnlockFailed)? };
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| VaultError::UnlockFailed)?;
        let mut payload = self.wrapped_cmk.clone();
        cipher.decrypt_in_place(XNonce::from_slice(&self.nonce), &slot_aad(self.kind, kdf, salt), &mut payload).map_err(|_| VaultError::UnlockFailed)?;
        let cmk: [u8; KEY_LENGTH] = payload.try_into().map_err(|_| VaultError::UnlockFailed)?;
        Ok(Zeroizing::new(cmk))
    }
}

/// An opened container owns the advisory lock and the only in-process copy of CMK.
pub struct Container {
    root: PathBuf,
    lock: File,
    cmk: Zeroizing<[u8; KEY_LENGTH]>,
    header: Header,
    identity: Identity,
}

impl Container {
    pub fn create(path: impl AsRef<Path>, password: &[u8]) -> Result<(Self, String), VaultError> {
        Self::create_internal(path, password, None)
    }

    pub fn create_with_keyfile(path: impl AsRef<Path>, password: &[u8], keyfile: &[u8]) -> Result<(Self, String), VaultError> {
        Self::create_internal(path, password, Some(keyfile))
    }

    fn create_internal(path: impl AsRef<Path>, password: &[u8], keyfile: Option<&[u8]>) -> Result<(Self, String), VaultError> {
        if password.len() < 12 { return Err(VaultError::UnlockFailed); }
        let unlock_key = password_material(password, keyfile)?;
        let root = path.as_ref().to_path_buf();
        if root.exists() { return Err(VaultError::AlreadyExists); }
        fs::create_dir_all(root.join(INDEX_DIR))?;
        fs::create_dir_all(root.join(SEGMENT_DIR))?;
        let mut cmk = Zeroizing::new([0u8; KEY_LENGTH]); OsRng.fill_bytes(cmk.as_mut());
        let (header, recovery_key) = Header::new_with_unlock_key(&cmk, &unlock_key, keyfile.is_some())?;
        write_atomic(&root.join(HEADER_NAME), &header.encode()?)?;
        let identity = Identity::generate();
        write_identity(&root, &cmk, &identity)?;
        let lock = acquire_lock(&root)?;
        let container = Self { root, lock, cmk, header, identity };
        Ok((container, recovery_key))
    }

    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Self, VaultError> {
        let unlock_key = password_material(password, None)?;
        Self::open_with_password_material(path, &unlock_key, false)
    }

    pub fn open_with_keyfile(path: impl AsRef<Path>, password: &[u8], keyfile: &[u8]) -> Result<Self, VaultError> {
        let unlock_key = password_material(password, Some(keyfile))?;
        Self::open_with_password_material(path, &unlock_key, true)
    }

    fn open_with_password_material(path: impl AsRef<Path>, unlock_key: &[u8], keyfile_supplied: bool) -> Result<Self, VaultError> {
        let root = path.as_ref().to_path_buf();
        if !root.is_dir() { return Err(VaultError::NotFound); }
        let lock = acquire_lock(&root)?;
        let header = read_header(&root)?;
        if header.keyfile_required != keyfile_supplied { delay_after_auth_failure(&root); return Err(VaultError::UnlockFailed); }
        let slot = header.slot(SLOT_PASSWORD).ok_or(VaultError::InvalidFormat)?;
        let cmk = match slot.unwrap(unlock_key, header.kdf, &header.salt) {
            Ok(cmk) => { clear_auth_failures(&root); cmk }
            Err(error) => { delay_after_auth_failure(&root); return Err(error); }
        };
        Self::finish_open(root, lock, header, cmk)
    }

    pub fn open_with_recovery(path: impl AsRef<Path>, recovery_key: &str) -> Result<Self, VaultError> {
        let root = path.as_ref().to_path_buf();
        if !root.is_dir() { return Err(VaultError::NotFound); }
        let lock = acquire_lock(&root)?;
        let header = read_header(&root)?;
        let recovery = match decode_recovery_key(recovery_key) {
            Ok(recovery) => recovery,
            Err(_) => { delay_after_auth_failure(&root); return Err(VaultError::UnlockFailed); }
        };
        let slot = header.slot(SLOT_RECOVERY).ok_or(VaultError::InvalidFormat)?;
        let cmk = match slot.unwrap(&recovery, header.kdf, &header.salt) {
            Ok(cmk) => { clear_auth_failures(&root); cmk }
            Err(error) => { delay_after_auth_failure(&root); return Err(error); }
        };
        Self::finish_open(root, lock, header, cmk)
    }

    fn finish_open(root: PathBuf, lock: File, header: Header, cmk: Zeroizing<[u8; KEY_LENGTH]>) -> Result<Self, VaultError> {
        recover_segment_tail(&root)?;
        let identity = load_or_create_identity(&root, &cmk)?;
        Ok(Self { root, lock, cmk, header, identity })
    }

    pub fn identity(&self) -> &Identity { &self.identity }

    pub fn export_header_backup(&self) -> Result<Vec<u8>, VaultError> {
        let header = self.header.encode()?;
        let identity = fs::read(self.root.join(IDENTITY_NAME))?;
        if header.len() > MAX_BACKUP_COMPONENT_BYTES || identity.len() > MAX_BACKUP_COMPONENT_BYTES { return Err(VaultError::InvalidFormat); }
        let mut backup = Vec::with_capacity(16 + header.len() + identity.len());
        backup.extend_from_slice(BACKUP_MAGIC);
        put_u32(&mut backup, header.len() as u32);
        backup.extend_from_slice(&header);
        put_u32(&mut backup, identity.len() as u32);
        backup.extend_from_slice(&identity);
        Ok(backup)
    }

    pub fn restore_header_backup(path: impl AsRef<Path>, backup: &[u8]) -> Result<(), VaultError> {
        let root = path.as_ref();
        if !root.is_dir() { return Err(VaultError::NotFound); }
        let (header, identity) = decode_header_backup(backup)?;
        let lock = acquire_lock(root)?;
        write_atomic(&root.join(HEADER_NAME), &header)?;
        write_atomic(&root.join(IDENTITY_NAME), &identity)?;
        drop(lock);
        Ok(())
    }

    pub fn sign_manifest(&self, manifest_id: [u8; 32], swarm_id: [u8; 32], object_id: ObjectId) -> [u8; 64] {
        self.identity.sign(&manifest_signing_bytes(&manifest_id, &swarm_id, object_id.as_bytes()))
    }

    pub fn revoked_epoch(&self, swarm_id: [u8; 32]) -> Result<u64, VaultError> {
        Ok(read_revocations(&self.root, &self.cmk)?.into_iter().find(|entry| entry.0 == swarm_id).map_or(0, |entry| entry.1))
    }

    pub fn revoke_swarm(&self, swarm_id: [u8; 32]) -> Result<u64, VaultError> {
        let mut revocations = read_revocations(&self.root, &self.cmk)?;
        let epoch = match revocations.iter_mut().find(|entry| entry.0 == swarm_id) {
            Some(entry) => { entry.1 = entry.1.checked_add(1).ok_or(VaultError::InvalidFormat)?; entry.1 }
            None => { revocations.push((swarm_id, 1)); 1 }
        };
        write_revocations(&self.root, &self.cmk, &mut revocations)?;
        Ok(epoch)
    }

    pub fn block_size(&self) -> usize { self.header.block_size as usize }

    pub fn import_bytes(&self, name: &str, plaintext: &[u8]) -> Result<ObjectInfo, VaultError> {
        self.import_reader(name, plaintext.len() as u64, Cursor::new(plaintext))
    }

    pub fn import_reader<R: Read>(&self, name: &str, plaintext_len: u64, mut reader: R) -> Result<ObjectInfo, VaultError> {
        validate_name(name)?;
        if self.list_objects()?.iter().any(|object| object.name == name) || self.list_folders()?.iter().any(|folder| folder == name) { return Err(VaultError::AlreadyExists); }
        if plaintext_len > u32::MAX as u64 { return Err(VaultError::FileTooLarge); }
        let object_id = ObjectId::random();
        let mut cek = Zeroizing::new([0u8; KEY_LENGTH]); OsRng.fill_bytes(cek.as_mut());
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LENGTH]; OsRng.fill_bytes(&mut nonce_prefix);
        let segment_path = self.root.join(SEGMENT_DIR).join(SEGMENT_NAME);
        let mut segment = OpenOptions::new().create(true).append(true).read(true).open(&segment_path)?;
        let mut locations = Vec::new();
        let mut block_ids = Vec::new();
        let mut remaining = plaintext_len;
        let mut index = 0u64;
        loop {
            let requested = remaining.min(self.block_size() as u64) as usize;
            let mut block = Zeroizing::new(vec![0u8; requested]);
            if requested != 0 { reader.read_exact(&mut block).map_err(|error| if error.kind() == io::ErrorKind::UnexpectedEof { VaultError::LengthMismatch } else { VaultError::Io(error) })?; }
            let is_last = remaining <= self.block_size() as u64;
            if is_last {
                let padded = if block.is_empty() { 0 } else { block.len().div_ceil(PAD_UNIT) * PAD_UNIT };
                block.resize(padded, 0);
            }
            let nonce = block_nonce(&nonce_prefix, index, is_last);
            let aad = block_aad(&object_id, index, is_last, plaintext_len);
            let cipher = XChaCha20Poly1305::new_from_slice(cek.as_ref()).map_err(|_| VaultError::Crypto)?;
            cipher.encrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut *block).map_err(|_| VaultError::Crypto)?;
            let block_id = *blake3::hash(&block).as_bytes();
            let offset = segment.seek(SeekFrom::End(0))?;
            put_u32_to_writer(&mut segment, block.len() as u32)?;
            segment.write_all(&block_id)?;
            segment.write_all(&block)?;
            locations.push(BlockLocation { offset, len: block.len() as u32 });
            block_ids.push(block_id);
            if is_last { break; }
            remaining -= requested as u64;
            index += 1;
        }
        let mut extra = [0u8; 1];
        if reader.read(&mut extra)? != 0 { return Err(VaultError::LengthMismatch); }
        segment.sync_all()?;
        let manifest = encode_manifest(name, &object_id, plaintext_len, self.block_size() as u32, &nonce_prefix, &block_ids);
        let mut manifest_nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut manifest_nonce);
        let manifest_ciphertext = encrypt(&cek, &manifest_nonce, [MANIFEST_AAD, object_id.as_bytes()].concat(), manifest)?;
        let record = encode_index_record(name, &object_id, plaintext_len, self.block_size() as u32, &cek, &manifest_nonce, &manifest_ciphertext, &block_ids, &locations)?;
        // shortcut: M1 keeps one append-only segment and one encrypted index record per object.
        let index_path = self.index_path(&object_id);
        let index_key = self.derive_index_key()?;
        let mut index_nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut index_nonce);
        let encrypted_record = encrypt(&index_key, &index_nonce, [INDEX_AAD, object_id.as_bytes()].concat(), record)?;
        let mut index_file = Vec::with_capacity(NONCE_LENGTH + encrypted_record.len()); index_file.extend_from_slice(&index_nonce); index_file.extend_from_slice(&encrypted_record);
        write_atomic(&index_path, &index_file)?;
        sync_dir(&self.root.join(INDEX_DIR))?;
        Ok(ObjectInfo { id: object_id, name: name.to_owned(), plaintext_len, block_count: block_ids.len() })
    }

    pub fn copy_object(&self, id: ObjectId, name: &str) -> Result<ObjectInfo, VaultError> {
        validate_name(name)?;
        if self.list_objects()?.iter().any(|object| object.name == name) || self.list_folders()?.iter().any(|folder| folder == name) { return Err(VaultError::AlreadyExists); }
        let mut reader = ObjectPlaintextReader::open(self, id)?;
        let plaintext_len = reader.plaintext_len();
        self.import_reader(name, plaintext_len, &mut reader)
    }

    pub fn list_objects(&self) -> Result<Vec<ObjectInfo>, VaultError> {
        let mut objects = Vec::new();
        for entry in fs::read_dir(self.root.join(INDEX_DIR))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() || entry.path().extension().and_then(|ext| ext.to_str()) != Some("idx") { continue; }
            let record = self.read_index_record(&entry.path())?;
            let (info, _) = decode_index_record(&record)?;
            objects.push(info);
        }
        objects.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(objects)
    }

    pub fn rename_object(&self, id: ObjectId, name: &str) -> Result<ObjectInfo, VaultError> {
        validate_name(name)?;
        if self.list_objects()?.into_iter().any(|object| object.id != id && object.name == name) || self.list_folders()?.iter().any(|folder| folder == name) {
            return Err(VaultError::AlreadyExists);
        }
        let record = self.read_index_record(&self.index_path(&id))?;
        let (_, stored) = decode_index_record(&record)?;
        let manifest_bytes = decrypt(&stored.cek, &stored.manifest_nonce, [MANIFEST_AAD, id.as_bytes()].concat(), &stored.manifest_ciphertext)?;
        let manifest = decode_manifest(&manifest_bytes)?;
        if manifest.object_id != id { return Err(VaultError::Integrity); }
        let plaintext_len = manifest.plaintext_len;
        let block_size = manifest.block_size;
        let nonce_prefix = manifest.nonce_prefix;
        let block_ids = manifest.block_ids;
        let manifest = encode_manifest(name, &id, plaintext_len, block_size, &nonce_prefix, &block_ids);
        let mut manifest_nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut manifest_nonce);
        let manifest_ciphertext = encrypt(&stored.cek, &manifest_nonce, [MANIFEST_AAD, id.as_bytes()].concat(), manifest)?;
        let index_record = encode_index_record(name, &id, plaintext_len, block_size, &stored.cek, &manifest_nonce, &manifest_ciphertext, &block_ids, &stored.locations)?;
        let index_key = self.derive_index_key()?;
        let mut index_nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut index_nonce);
        let encrypted_record = encrypt(&index_key, &index_nonce, [INDEX_AAD, id.as_bytes()].concat(), index_record)?;
        let mut index_file = Vec::with_capacity(NONCE_LENGTH + encrypted_record.len()); index_file.extend_from_slice(&index_nonce); index_file.extend_from_slice(&encrypted_record);
        write_atomic(&self.index_path(&id), &index_file)?;
        Ok(ObjectInfo { id, name: name.to_owned(), plaintext_len, block_count: block_ids.len() })
    }

    pub fn delete_object(&self, id: ObjectId) -> Result<(), VaultError> {
        let path = self.index_path(&id);
        if !path.exists() { return Err(VaultError::NotFound); }
        fs::remove_file(path)?;
        sync_dir(&self.root.join(INDEX_DIR))
    }

    pub fn compact(&self) -> Result<(), VaultError> {
        recover_compaction(&self.root)?;
        let active_index = self.root.join(INDEX_DIR);
        let staged_index = compaction_staged_index(&self.root);
        let old_index = compaction_old_index(&self.root);
        let segment_dir = self.root.join(SEGMENT_DIR);
        let active_segment = segment_dir.join(SEGMENT_NAME);
        let staged_segment = compaction_staged_segment(&self.root);
        let old_segment = compaction_old_segment(&self.root);
        if old_index.exists() || old_segment.exists() { return Err(VaultError::InvalidFormat); }
        if staged_index.exists() { fs::remove_dir_all(&staged_index)?; }
        if staged_segment.exists() { fs::remove_file(&staged_segment)?; }
        fs::create_dir_all(&staged_index)?;
        let mut source = if active_segment.exists() { Some(File::open(&active_segment)?) } else { None };
        let mut target = OpenOptions::new().create_new(true).write(true).read(true).open(&staged_segment)?;
        let index_key = self.derive_index_key()?;
        for entry in fs::read_dir(&active_index)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() || entry.path().extension().and_then(|ext| ext.to_str()) != Some("idx") { continue; }
            let path = entry.path();
            let record = self.read_index_record(&path)?;
            let (info, stored) = decode_index_record(&record)?;
            let manifest_bytes = decrypt(&stored.cek, &stored.manifest_nonce, [MANIFEST_AAD, info.id.as_bytes()].concat(), &stored.manifest_ciphertext)?;
            let manifest = decode_manifest(&manifest_bytes)?;
            if manifest.object_id != info.id || manifest.block_ids.len() != stored.locations.len() { return Err(VaultError::Integrity); }
            let source = source.as_mut().ok_or(VaultError::Integrity)?;
            let mut locations = Vec::with_capacity(stored.locations.len());
            for (block_id, location) in manifest.block_ids.iter().zip(&stored.locations) {
                let ciphertext = read_segment_block(source, location, block_id)?;
                let offset = target.seek(SeekFrom::End(0))?;
                target.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
                target.write_all(block_id)?;
                target.write_all(&ciphertext)?;
                locations.push(BlockLocation { offset, len: ciphertext.len() as u32 });
            }
            let new_record = encode_index_record(&info.name, &info.id, info.plaintext_len, manifest.block_size, &stored.cek, &stored.manifest_nonce, &stored.manifest_ciphertext, &manifest.block_ids, &locations)?;
            let mut nonce = [0u8; NONCE_LENGTH];
            OsRng.fill_bytes(&mut nonce);
            let encrypted = encrypt(&index_key, &nonce, [INDEX_AAD, info.id.as_bytes()].concat(), new_record)?;
            let mut file = Vec::with_capacity(NONCE_LENGTH + encrypted.len());
            file.extend_from_slice(&nonce);
            file.extend_from_slice(&encrypted);
            write_atomic(&staged_index.join(entry.file_name()), &file)?;
        }
        target.sync_all()?;
        sync_dir(&staged_index)?;
        sync_dir(&segment_dir)?;
        write_compaction_journal(&self.root, COMPACTION_PREPARED)?;
        if active_segment.exists() { fs::rename(&active_segment, &old_segment)?; }
        fs::rename(&staged_segment, &active_segment)?;
        sync_dir(&segment_dir)?;
        write_compaction_journal(&self.root, COMPACTION_SEGMENT_SWAPPED)?;
        fs::rename(&active_index, &old_index)?;
        fs::rename(&staged_index, &active_index)?;
        sync_dir(active_index.parent().ok_or(VaultError::InvalidFormat)?)?;
        write_compaction_journal(&self.root, COMPACTION_INDEX_SWAPPED)?;
        if old_index.exists() { fs::remove_dir_all(old_index)?; }
        if old_segment.exists() { fs::remove_file(old_segment)?; }
        sync_dir(active_index.parent().ok_or(VaultError::InvalidFormat)?)?;
        sync_dir(&segment_dir)?;
        fs::remove_file(compaction_journal_path(&self.root))?;
        sync_dir(&self.root)
    }

    pub fn list_folders(&self) -> Result<Vec<String>, VaultError> { read_folders(&self.root, &self.cmk) }

    pub fn create_folder(&self, path: &str) -> Result<Vec<String>, VaultError> {
        validate_name(path)?;
        let mut folders = read_folders(&self.root, &self.cmk)?;
        if folders.iter().any(|folder| folder == path) { return Err(VaultError::AlreadyExists); }
        for object in self.list_objects()? {
            if path == object.name || path.starts_with(&format!("{}/", object.name)) { return Err(VaultError::AlreadyExists); }
        }
        for component in path.split('/').scan(String::new(), |prefix, part| {
            if !prefix.is_empty() { prefix.push('/'); }
            prefix.push_str(part);
            Some(prefix.clone())
        }) {
            if !folders.iter().any(|folder| folder == &component) { folders.push(component); }
        }
        write_folders(&self.root, &self.cmk, &mut folders)?;
        Ok(folders)
    }

    pub fn rename_folder(&self, old_path: &str, new_path: &str) -> Result<Vec<String>, VaultError> {
        validate_name(old_path)?;
        validate_name(new_path)?;
        let mut folders = read_folders(&self.root, &self.cmk)?;
        if !folders.iter().any(|folder| folder == old_path) { return Err(VaultError::NotFound); }
        if new_path.starts_with(&format!("{}/", old_path)) { return Err(VaultError::InvalidFormat); }
        let objects = self.list_objects()?;
        let affected_folders = folders.iter().filter(|folder| folder.as_str() == old_path || folder.starts_with(&format!("{}/", old_path))).cloned().collect::<Vec<_>>();
        let affected_objects = objects.iter().filter(|object| object.name == old_path || object.name.starts_with(&format!("{}/", old_path))).cloned().collect::<Vec<_>>();
        let mapped_folders = affected_folders.iter().map(|folder| replace_path_prefix(folder, old_path, new_path)).collect::<Vec<_>>();
        let mapped_objects = affected_objects.iter().map(|object| replace_path_prefix(&object.name, old_path, new_path)).collect::<Vec<_>>();
        if mapped_folders.iter().any(|folder| folders.iter().any(|current| !affected_folders.iter().any(|affected| affected == current) && current == folder)) || mapped_folders.iter().any(|folder| objects.iter().any(|object| !affected_objects.iter().any(|affected| affected.id == object.id) && object.name.as_str() == folder.as_str())) || mapped_objects.iter().any(|name| objects.iter().any(|object| !affected_objects.iter().any(|affected| affected.id == object.id) && object.name.as_str() == name.as_str())) { return Err(VaultError::AlreadyExists); }
        if mapped_objects.iter().any(|name| mapped_folders.iter().any(|folder| folder == name)) { return Err(VaultError::AlreadyExists); }
        let mut renamed: Vec<(ObjectId, String)> = Vec::new();
        for (object, name) in affected_objects.iter().zip(&mapped_objects) {
            if let Err(error) = self.rename_object(object.id, name) {
                for (id, old_name) in renamed.into_iter().rev() { let _ = self.rename_object(id, &old_name); }
                return Err(error);
            }
            renamed.push((object.id, object.name.clone()));
        }
        folders.retain(|folder| !affected_folders.iter().any(|affected| affected == folder));
        folders.extend(mapped_folders);
        for component in new_path.split('/').scan(String::new(), |prefix, part| {
            if !prefix.is_empty() { prefix.push('/'); }
            prefix.push_str(part);
            Some(prefix.clone())
        }) {
            if !folders.iter().any(|folder| folder == &component) { folders.push(component); }
        }
        if let Err(error) = write_folders(&self.root, &self.cmk, &mut folders) {
            for (id, old_name) in renamed.into_iter().rev() { let _ = self.rename_object(id, &old_name); }
            return Err(error);
        }
        Ok(folders)
    }

    pub fn delete_folder(&self, path: &str) -> Result<Vec<String>, VaultError> {
        validate_name(path)?;
        let mut folders = read_folders(&self.root, &self.cmk)?;
        if !folders.iter().any(|folder| folder == path) { return Err(VaultError::NotFound); }
        let objects = self.list_objects()?;
        let affected_objects = objects.iter().filter(|object| object.name == path || object.name.starts_with(&format!("{}/", path))).map(|object| object.id).collect::<Vec<_>>();
        for id in affected_objects { self.delete_object(id)?; }
        folders.retain(|folder| folder != path && !folder.starts_with(&format!("{}/", path)));
        write_folders(&self.root, &self.cmk, &mut folders)?;
        Ok(folders)
    }

    pub fn change_password(&mut self, password: &[u8]) -> Result<(), VaultError> {
        self.change_password_with_material(password, None)
    }

    pub fn change_password_with_keyfile(&mut self, password: &[u8], keyfile: &[u8]) -> Result<(), VaultError> {
        self.change_password_with_material(password, Some(keyfile))
    }

    fn change_password_with_material(&mut self, password: &[u8], keyfile: Option<&[u8]>) -> Result<(), VaultError> {
        if password.len() < 12 { return Err(VaultError::UnlockFailed); }
        if self.header.keyfile_required != keyfile.is_some() { return Err(VaultError::UnlockFailed); }
        let unlock_key = password_material(password, keyfile)?;
        let mut header = self.header.clone();
        let slot = KeySlot::wrap(SLOT_PASSWORD, &unlock_key, &self.cmk, header.kdf, &header.salt)?;
        let index = header.slots.iter().position(|candidate| candidate.kind == SLOT_PASSWORD).ok_or(VaultError::InvalidFormat)?;
        header.slots[index] = slot;
        write_atomic(&self.root.join(HEADER_NAME), &header.encode()?)?;
        self.header = header;
        Ok(())
    }

    pub fn rotate_recovery_key(&mut self) -> Result<String, VaultError> {
        let mut recovery = [0u8; KEY_LENGTH]; OsRng.fill_bytes(&mut recovery);
        let encoded = encode_recovery_key(&recovery);
        let result = (|| {
            let mut header = self.header.clone();
            let slot = KeySlot::wrap(SLOT_RECOVERY, &recovery, &self.cmk, header.kdf, &header.salt)?;
            let index = header.slots.iter().position(|candidate| candidate.kind == SLOT_RECOVERY).ok_or(VaultError::InvalidFormat)?;
            header.slots[index] = slot;
            write_atomic(&self.root.join(HEADER_NAME), &header.encode()?)?;
            self.header = header;
            Ok(encoded)
        })();
        recovery.zeroize();
        result
    }

    pub fn rotate_cmk(&mut self, password: &[u8], recovery_key: &str) -> Result<(), VaultError> {
        self.rotate_cmk_with_material(password, recovery_key, None)
    }

    pub fn rotate_cmk_with_keyfile(&mut self, password: &[u8], recovery_key: &str, keyfile: &[u8]) -> Result<(), VaultError> {
        self.rotate_cmk_with_material(password, recovery_key, Some(keyfile))
    }

    fn rotate_cmk_with_material(&mut self, password: &[u8], recovery_key: &str, keyfile: Option<&[u8]>) -> Result<(), VaultError> {
        if password.len() < 12 { return Err(VaultError::UnlockFailed); }
        if self.header.keyfile_required != keyfile.is_some() { return Err(VaultError::UnlockFailed); }
        let unlock_key = password_material(password, keyfile)?;
        let password_cmk = self.header.slot(SLOT_PASSWORD).ok_or(VaultError::InvalidFormat)?.unwrap(&unlock_key, self.header.kdf, &self.header.salt)?;
        let mut recovery = decode_recovery_key(recovery_key).map_err(|_| VaultError::UnlockFailed)?;
        let result = (|| {
            let recovery_cmk = self.header.slot(SLOT_RECOVERY).ok_or(VaultError::InvalidFormat)?.unwrap(&recovery, self.header.kdf, &self.header.salt)?;
            if password_cmk.as_ref() != self.cmk.as_ref() || recovery_cmk.as_ref() != self.cmk.as_ref() { return Err(VaultError::UnlockFailed); }

            let mut new_cmk = Zeroizing::new([0u8; KEY_LENGTH]);
            OsRng.fill_bytes(new_cmk.as_mut());
            recover_rotation(&self.root)?;
            let staged_index = rotation_staged_index(&self.root);
            let old_index = rotation_old_index(&self.root);
            let staged_folders = rotation_staged_folders(&self.root);
            let old_folders = rotation_old_folders(&self.root);
            let staged_revocations = rotation_staged_revocations(&self.root);
            let old_revocations = rotation_old_revocations(&self.root);
            let staged_identity = rotation_staged_identity(&self.root);
            let old_identity = rotation_old_identity(&self.root);
            if old_index.exists() || old_folders.exists() || old_revocations.exists() || old_identity.exists() { return Err(VaultError::InvalidFormat); }
            if staged_index.exists() { fs::remove_dir_all(&staged_index)?; }
            if staged_folders.exists() { fs::remove_file(&staged_folders)?; }
            if staged_revocations.exists() { fs::remove_file(&staged_revocations)?; }
            if staged_identity.exists() { fs::remove_file(&staged_identity)?; }
            fs::create_dir_all(&staged_index)?;

            let index_key = derive_hkdf(&new_cmk, b"vault/v1/index-key")?;
            for entry in fs::read_dir(self.root.join(INDEX_DIR))? {
                let entry = entry?;
                let path = entry.path();
                if !entry.file_type()?.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("idx") { continue; }
                let stem = path.file_stem().and_then(|value| value.to_str()).ok_or(VaultError::InvalidFormat)?;
                let object_id = ObjectId::from_bytes(decode_hex_16(stem)?);
                let record = self.read_index_record(&path)?;
                let (info, _) = decode_index_record(&record)?;
                if info.id != object_id { return Err(VaultError::Integrity); }
                let mut nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut nonce);
                let encrypted = encrypt(&index_key, &nonce, [INDEX_AAD, object_id.as_bytes()].concat(), record)?;
                let mut file = Vec::with_capacity(NONCE_LENGTH + encrypted.len());
                file.extend_from_slice(&nonce);
                file.extend_from_slice(&encrypted);
                write_atomic(&staged_index.join(entry.file_name()), &file)?;
            }
            sync_dir(&staged_index)?;
            let folders = read_folders(&self.root, &self.cmk)?;
            write_encrypted_folders(&staged_folders, &new_cmk, &folders)?;
            let revocations = read_revocations(&self.root, &self.cmk)?;
            write_encrypted_revocations(&staged_revocations, &new_cmk, &revocations)?;
            write_atomic(&staged_identity, &encrypted_identity_file(&new_cmk, &self.identity)?)?;

            let mut new_header = self.header.clone();
            let password_slot = KeySlot::wrap(SLOT_PASSWORD, &unlock_key, &new_cmk, new_header.kdf, &new_header.salt)?;
            let password_index = new_header.slots.iter().position(|slot| slot.kind == SLOT_PASSWORD).ok_or(VaultError::InvalidFormat)?;
            new_header.slots[password_index] = password_slot;
            let recovery_slot = KeySlot::wrap(SLOT_RECOVERY, &recovery, &new_cmk, new_header.kdf, &new_header.salt)?;
            let recovery_index = new_header.slots.iter().position(|slot| slot.kind == SLOT_RECOVERY).ok_or(VaultError::InvalidFormat)?;
            new_header.slots[recovery_index] = recovery_slot;
            let old_header = self.header.encode()?;
            let new_header_bytes = new_header.encode()?;
            write_rotation_journal(&self.root, &RotationJournal { phase: ROTATION_PREPARED, old_header: old_header.clone(), new_header: new_header_bytes.clone() })?;

            let active_index = self.root.join(INDEX_DIR);
            fs::rename(&active_index, &old_index)?;
            fs::rename(&staged_index, &active_index)?;
            let active_folders = folder_index_path(&self.root);
            if active_folders.exists() { fs::rename(&active_folders, &old_folders)?; }
            fs::rename(&staged_folders, &active_folders)?;
            let active_revocations = revocation_index_path(&self.root);
            if active_revocations.exists() { fs::rename(&active_revocations, &old_revocations)?; }
            fs::rename(&staged_revocations, &active_revocations)?;
            sync_dir(active_index.parent().ok_or(VaultError::InvalidFormat)?)?;
            write_rotation_journal(&self.root, &RotationJournal { phase: ROTATION_INDEX_SWAPPED, old_header: old_header.clone(), new_header: new_header_bytes.clone() })?;

            let active_identity = self.root.join(IDENTITY_NAME);
            fs::rename(&active_identity, &old_identity)?;
            fs::rename(&staged_identity, &active_identity)?;
            sync_dir(&self.root)?;
            write_rotation_journal(&self.root, &RotationJournal { phase: ROTATION_IDENTITY_SWAPPED, old_header: old_header.clone(), new_header: new_header_bytes.clone() })?;

            write_atomic(&self.root.join(HEADER_NAME), &new_header_bytes)?;
            write_rotation_journal(&self.root, &RotationJournal { phase: ROTATION_HEADER_SWAPPED, old_header, new_header: new_header_bytes })?;
            self.cmk = new_cmk;
            self.header = new_header;
            if old_index.exists() { let _ = fs::remove_dir_all(old_index); }
            if staged_index.exists() { let _ = fs::remove_dir_all(staged_index); }
            if old_folders.exists() { let _ = fs::remove_file(old_folders); }
            if staged_folders.exists() { let _ = fs::remove_file(staged_folders); }
            if old_revocations.exists() { let _ = fs::remove_file(old_revocations); }
            if staged_revocations.exists() { let _ = fs::remove_file(staged_revocations); }
            if old_identity.exists() { let _ = fs::remove_file(old_identity); }
            if staged_identity.exists() { let _ = fs::remove_file(staged_identity); }
            let _ = fs::remove_file(rotation_journal_path(&self.root));
            let _ = sync_dir(&self.root);
            Ok(())
        })();
        recovery.zeroize();
        result
    }

    pub fn export_bytes(&self, id: ObjectId) -> Result<Vec<u8>, VaultError> {
        let record = self.read_index_record(&self.index_path(&id))?;
        let (_, stored) = decode_index_record(&record)?;
        let manifest_bytes = decrypt(&stored.cek, &stored.manifest_nonce, [MANIFEST_AAD, id.as_bytes()].concat(), &stored.manifest_ciphertext)?;
        let manifest = decode_manifest(&manifest_bytes)?;
        if manifest.object_id != id || manifest.block_ids.len() != stored.locations.len() { return Err(VaultError::Integrity); }
        let mut output = Vec::with_capacity(manifest.plaintext_len as usize);
        let segment_path = self.root.join(SEGMENT_DIR).join(SEGMENT_NAME);
        let mut segment = File::open(segment_path)?;
        for (index, (block_id, location)) in manifest.block_ids.iter().zip(stored.locations.iter()).enumerate() {
            let ciphertext = read_segment_block(&mut segment, location, block_id)?;
            let nonce = block_nonce(&manifest.nonce_prefix, index as u64, index + 1 == manifest.block_ids.len());
            let aad = block_aad(&id, index as u64, index + 1 == manifest.block_ids.len(), manifest.plaintext_len);
            let plaintext = decrypt(&stored.cek, &nonce, aad, &ciphertext)?;
            output.extend_from_slice(&plaintext);
        }
        output.truncate(manifest.plaintext_len as usize);
        if output.len() != manifest.plaintext_len as usize { return Err(VaultError::Integrity); }
        Ok(output)
    }

    pub fn share_material(&self, id: ObjectId) -> Result<ObjectShareMaterial, VaultError> {
        let record = self.read_index_record(&self.index_path(&id))?;
        let (info, stored) = decode_index_record(&record)?;
        if info.id != id { return Err(VaultError::Integrity); }
        Ok(ObjectShareMaterial { cek: stored.cek, manifest_id: *blake3::hash(&stored.manifest_ciphertext).as_bytes() })
    }

    pub fn read_encrypted_object(&self, id: ObjectId) -> Result<EncryptedObject, VaultError> {
        let record = self.read_index_record(&self.index_path(&id))?;
        let (info, mut stored) = decode_index_record(&record)?;
        if info.id != id { return Err(VaultError::Integrity); }
        let manifest_bytes = decrypt(&stored.cek, &stored.manifest_nonce, [MANIFEST_AAD, id.as_bytes()].concat(), &stored.manifest_ciphertext)?;
        let manifest = decode_manifest(&manifest_bytes)?;
        if manifest.object_id != id || manifest.block_ids.len() != stored.locations.len() { return Err(VaultError::Integrity); }
        let mut segment = File::open(self.root.join(SEGMENT_DIR).join(SEGMENT_NAME))?;
        let mut blocks = Vec::with_capacity(manifest.block_ids.len());
        for (expected_id, location) in manifest.block_ids.iter().zip(stored.locations.iter()) {
            let bytes = read_segment_block(&mut segment, location, expected_id)?;
            blocks.push(EncryptedBlock { id: *expected_id, bytes });
        }
        let manifest_ciphertext = std::mem::take(&mut stored.manifest_ciphertext);
        Ok(EncryptedObject { manifest_id: *blake3::hash(&manifest_ciphertext).as_bytes(), manifest_nonce: stored.manifest_nonce, manifest_ciphertext, blocks })
    }

    pub fn save_transfer_checkpoint(&self, id: ObjectId, checkpoint: &TransferCheckpoint) -> Result<(), VaultError> {
        if checkpoint.manifest_ciphertext.len() < TAG_LENGTH || checkpoint.manifest_ciphertext.len() > 64 * 1024 * 1024 || *blake3::hash(&checkpoint.manifest_ciphertext).as_bytes() != checkpoint.manifest_id || checkpoint.blocks.len() > 4 * 1024 * 1024 { return Err(VaultError::Integrity); }
        let manifest = inspect_encrypted_manifest(id, checkpoint.manifest_id, checkpoint.cek, checkpoint.manifest_nonce, &checkpoint.manifest_ciphertext)?;
        if manifest.block_ids.len() < checkpoint.blocks.len() { return Err(VaultError::Integrity); }
        let mut seen = Vec::with_capacity(checkpoint.blocks.len());
        for block in &checkpoint.blocks {
            if !manifest.block_ids.contains(&block.id) || block.bytes.len() < TAG_LENGTH || block.bytes.len() > MAX_BLOCK_SIZE + TAG_LENGTH || *blake3::hash(&block.bytes).as_bytes() != block.id { return Err(VaultError::Integrity); }
            if seen.contains(&block.id) { return Err(VaultError::Integrity); }
            seen.push(block.id);
            let block_index = manifest.block_ids.iter().position(|id| id == &block.id).ok_or(VaultError::Integrity)?;
            let last = block_index + 1 == manifest.block_ids.len();
            let nonce = block_nonce(&manifest.nonce_prefix, block_index as u64, last);
            let aad = block_aad(&id, block_index as u64, last, manifest.plaintext_len);
            decrypt(&checkpoint.cek, &nonce, aad, &block.bytes)?;
        }
        fs::create_dir_all(self.root.join(TRANSFER_DIR))?;
        let record = encode_transfer_checkpoint(id, checkpoint)?;
        let key = self.derive_index_key()?;
        let mut nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut nonce);
        let ciphertext = encrypt(&key, &nonce, [TRANSFER_AAD, id.as_bytes()].concat(), record)?;
        let mut file = Vec::with_capacity(NONCE_LENGTH + ciphertext.len()); file.extend_from_slice(&nonce); file.extend_from_slice(&ciphertext);
        write_atomic(&self.transfer_checkpoint_path(&id), &file)
    }

    pub fn load_transfer_checkpoint(&self, id: ObjectId) -> Result<Option<TransferCheckpoint>, VaultError> {
        let path = self.transfer_checkpoint_path(&id);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(VaultError::Io(error)),
        };
        if bytes.len() < NONCE_LENGTH + TAG_LENGTH { return Err(VaultError::Integrity); }
        let nonce: [u8; NONCE_LENGTH] = bytes[..NONCE_LENGTH].try_into().map_err(|_| VaultError::Integrity)?;
        let key = self.derive_index_key()?;
        let record = decrypt(&key, &nonce, [TRANSFER_AAD, id.as_bytes()].concat(), &bytes[NONCE_LENGTH..])?;
        decode_transfer_checkpoint(id, &record).map(Some)
    }

    pub fn clear_transfer_checkpoint(&self, id: ObjectId) -> Result<(), VaultError> {
        let path = self.transfer_checkpoint_path(&id);
        match fs::remove_file(path) {
            Ok(()) => sync_dir(&self.root.join(TRANSFER_DIR)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(VaultError::Io(error)),
        }
    }

    pub fn import_encrypted_object(&self, id: ObjectId, expected_manifest_id: [u8; 32], cek: [u8; 32], manifest_nonce: [u8; 24], manifest_ciphertext: &[u8], blocks: &[EncryptedBlock]) -> Result<ObjectInfo, VaultError> {
        if self.index_path(&id).exists() || manifest_ciphertext.len() > 64 * 1024 * 1024 || blocks.len() > 4 * 1024 * 1024 || *blake3::hash(manifest_ciphertext).as_bytes() != expected_manifest_id { return Err(VaultError::Integrity); }
        let manifest_bytes = decrypt(&cek, &manifest_nonce, [MANIFEST_AAD, id.as_bytes()].concat(), manifest_ciphertext)?;
        let manifest = decode_manifest(&manifest_bytes)?;
        validate_name(&manifest.name)?;
        if self.list_objects()?.iter().any(|object| object.name == manifest.name) || self.list_folders()?.iter().any(|folder| folder == &manifest.name) { return Err(VaultError::AlreadyExists); }
        if manifest.object_id != id || manifest.block_ids.len() != blocks.len() { return Err(VaultError::Integrity); }
        for (index, (expected_id, block)) in manifest.block_ids.iter().zip(blocks).enumerate() {
            if block.id != *expected_id || block.bytes.len() < TAG_LENGTH || block.bytes.len() > MAX_BLOCK_SIZE + TAG_LENGTH || *blake3::hash(&block.bytes).as_bytes() != block.id { return Err(VaultError::Integrity); }
            let last = index + 1 == blocks.len();
            let nonce = block_nonce(&manifest.nonce_prefix, index as u64, last);
            let aad = block_aad(&id, index as u64, last, manifest.plaintext_len);
            decrypt(&cek, &nonce, aad, &block.bytes)?;
        }
        let segment_path = self.root.join(SEGMENT_DIR).join(SEGMENT_NAME);
        let mut segment = OpenOptions::new().create(true).append(true).read(true).open(segment_path)?;
        let mut locations = Vec::with_capacity(blocks.len());
        for block in blocks {
            let offset = segment.seek(SeekFrom::End(0))?;
            segment.write_all(&(block.bytes.len() as u32).to_le_bytes())?;
            segment.write_all(&block.id)?;
            segment.write_all(&block.bytes)?;
            locations.push(BlockLocation { offset, len: block.bytes.len() as u32 });
        }
        segment.sync_all()?;
        let record = encode_index_record(&manifest.name, &id, manifest.plaintext_len, manifest.block_size, &cek, &manifest_nonce, manifest_ciphertext, &manifest.block_ids, &locations)?;
        let index_key = self.derive_index_key()?;
        let mut index_nonce = [0u8; NONCE_LENGTH]; OsRng.fill_bytes(&mut index_nonce);
        let encrypted_record = encrypt(&index_key, &index_nonce, [INDEX_AAD, id.as_bytes()].concat(), record)?;
        let mut index_file = Vec::with_capacity(NONCE_LENGTH + encrypted_record.len()); index_file.extend_from_slice(&index_nonce); index_file.extend_from_slice(&encrypted_record);
        write_atomic(&self.index_path(&id), &index_file)?;
        Ok(ObjectInfo { id, name: manifest.name, plaintext_len: manifest.plaintext_len, block_count: manifest.block_ids.len() })
    }

    fn derive_index_key(&self) -> Result<Zeroizing<[u8; KEY_LENGTH]>, VaultError> { derive_hkdf(&self.cmk, b"vault/v1/index-key") }

    fn index_path(&self, id: &ObjectId) -> PathBuf { self.root.join(INDEX_DIR).join(format!("{}.idx", hex(id.as_bytes()))) }

    fn transfer_checkpoint_path(&self, id: &ObjectId) -> PathBuf { self.root.join(TRANSFER_DIR).join(format!("{}.part", hex(id.as_bytes()))) }

    fn read_index_record(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
        let stem = path.file_stem().and_then(|value| value.to_str()).ok_or(VaultError::InvalidFormat)?;
        let object_id = decode_hex_16(stem)?;
        let bytes = fs::read(path)?;
        if bytes.len() < NONCE_LENGTH + TAG_LENGTH { return Err(VaultError::Integrity); }
        let nonce: [u8; NONCE_LENGTH] = bytes[..NONCE_LENGTH].try_into().map_err(|_| VaultError::Integrity)?;
        let key = self.derive_index_key()?;
        decrypt(&key, &nonce, [INDEX_AAD, &object_id].concat(), &bytes[NONCE_LENGTH..])
    }
}

impl Drop for Container {
    fn drop(&mut self) { let _ = self.lock.unlock(); }
}

fn write_identity(root: &Path, cmk: &[u8; KEY_LENGTH], identity: &Identity) -> Result<(), VaultError> {
    write_atomic(&root.join(IDENTITY_NAME), &encrypted_identity_file(cmk, identity)?)
}

fn encrypted_identity_file(cmk: &[u8; KEY_LENGTH], identity: &Identity) -> Result<Vec<u8>, VaultError> {
    let key = derive_hkdf(cmk, b"vault/v1/identity-wrap-key")?;
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt(&key, &nonce, IDENTITY_AAD.to_vec(), encode_identity(identity))?;
    let mut file = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);
    Ok(file)
}

fn load_or_create_identity(root: &Path, cmk: &[u8; KEY_LENGTH]) -> Result<Identity, VaultError> {
    match fs::read(root.join(IDENTITY_NAME)) {
        Ok(bytes) => {
            if bytes.len() < NONCE_LENGTH + TAG_LENGTH { return Err(VaultError::InvalidFormat); }
            let nonce: [u8; NONCE_LENGTH] = bytes[..NONCE_LENGTH].try_into().map_err(|_| VaultError::InvalidFormat)?;
            let key = derive_hkdf(cmk, b"vault/v1/identity-wrap-key")?;
            let plaintext = decrypt(&key, &nonce, IDENTITY_AAD.to_vec(), &bytes[NONCE_LENGTH..])?;
            decode_identity(&plaintext)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let identity = Identity::generate();
            write_identity(root, cmk, &identity)?;
            Ok(identity)
        }
        Err(error) => Err(VaultError::Io(error)),
    }
}

fn encode_identity(identity: &Identity) -> Vec<u8> {
    let signing = identity.signing_secret_bytes();
    let hpke = identity.hpke_secret_bytes();
    let mut bytes = Vec::with_capacity(1 + KEY_LENGTH * 2);
    bytes.push(1);
    bytes.extend_from_slice(signing.as_ref());
    bytes.extend_from_slice(hpke.as_ref());
    bytes
}

fn decode_identity(bytes: &[u8]) -> Result<Identity, VaultError> {
    if bytes.len() != 1 + KEY_LENGTH * 2 || bytes[0] != 1 { return Err(VaultError::InvalidFormat); }
    let signing: [u8; KEY_LENGTH] = bytes[1..1 + KEY_LENGTH].try_into().map_err(|_| VaultError::InvalidFormat)?;
    let hpke: [u8; KEY_LENGTH] = bytes[1 + KEY_LENGTH..].try_into().map_err(|_| VaultError::InvalidFormat)?;
    Ok(Identity::from_secret_bytes(signing, hpke))
}

fn folder_index_path(root: &Path) -> PathBuf { root.join(FOLDER_INDEX_NAME) }

fn read_folders(root: &Path, cmk: &[u8; KEY_LENGTH]) -> Result<Vec<String>, VaultError> {
    let bytes = match fs::read(folder_index_path(root)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(VaultError::Io(error)),
    };
    if bytes.len() < NONCE_LENGTH + TAG_LENGTH { return Err(VaultError::Integrity); }
    let nonce: [u8; NONCE_LENGTH] = bytes[..NONCE_LENGTH].try_into().map_err(|_| VaultError::Integrity)?;
    let key = derive_hkdf(cmk, b"vault/v1/index-key")?;
    decode_folders(&decrypt(&key, &nonce, FOLDER_AAD.to_vec(), &bytes[NONCE_LENGTH..])?)
}

fn write_folders(root: &Path, cmk: &[u8; KEY_LENGTH], folders: &mut Vec<String>) -> Result<(), VaultError> {
    folders.sort();
    folders.dedup();
    if folders.len() > 65_535 { return Err(VaultError::InvalidFormat); }
    for folder in folders.iter() { validate_name(folder)?; }
    write_encrypted_folders(&folder_index_path(root), cmk, folders)
}

fn write_encrypted_folders(path: &Path, cmk: &[u8; KEY_LENGTH], folders: &[String]) -> Result<(), VaultError> {
    let key = derive_hkdf(cmk, b"vault/v1/index-key")?;
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt(&key, &nonce, FOLDER_AAD.to_vec(), encode_folders(folders))?;
    let mut file = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);
    write_atomic(path, &file)
}

fn encode_folders(folders: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1);
    put_u32(&mut out, folders.len() as u32);
    for folder in folders { put_bytes(&mut out, folder.as_bytes()); }
    out
}

fn decode_folders(bytes: &[u8]) -> Result<Vec<String>, VaultError> {
    let mut cursor = Cursor::new(bytes);
    if read_u8(&mut cursor)? != 1 { return Err(VaultError::InvalidFormat); }
    let count = read_u32(&mut cursor)? as usize;
    if count > 65_535 { return Err(VaultError::InvalidFormat); }
    let mut folders = Vec::with_capacity(count);
    for _ in 0..count {
        let folder = String::from_utf8(read_vec(&mut cursor)?).map_err(|_| VaultError::InvalidFormat)?;
        validate_name(&folder)?;
        folders.push(folder);
    }
    if cursor.position() != bytes.len() as u64 || folders.windows(2).any(|pair| pair[0].as_str() >= pair[1].as_str()) { return Err(VaultError::InvalidFormat); }
    Ok(folders)
}

fn revocation_index_path(root: &Path) -> PathBuf { root.join(REVOCATION_INDEX_NAME) }

fn read_revocations(root: &Path, cmk: &[u8; KEY_LENGTH]) -> Result<Vec<([u8; 32], u64)>, VaultError> {
    let bytes = match fs::read(revocation_index_path(root)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(VaultError::Io(error)),
    };
    if bytes.len() < NONCE_LENGTH + TAG_LENGTH { return Err(VaultError::Integrity); }
    let nonce: [u8; NONCE_LENGTH] = bytes[..NONCE_LENGTH].try_into().map_err(|_| VaultError::Integrity)?;
    let key = derive_hkdf(cmk, b"vault/v1/index-key")?;
    decode_revocations(&decrypt(&key, &nonce, REVOCATION_AAD.to_vec(), &bytes[NONCE_LENGTH..])?)
}

fn write_revocations(root: &Path, cmk: &[u8; KEY_LENGTH], revocations: &mut Vec<([u8; 32], u64)>) -> Result<(), VaultError> {
    revocations.sort_by_key(|entry| entry.0);
    revocations.dedup_by_key(|entry| entry.0);
    if revocations.len() > 65_535 || revocations.iter().any(|entry| entry.1 == 0) { return Err(VaultError::InvalidFormat); }
    write_encrypted_revocations(&revocation_index_path(root), cmk, revocations)
}

fn write_encrypted_revocations(path: &Path, cmk: &[u8; KEY_LENGTH], revocations: &[([u8; 32], u64)]) -> Result<(), VaultError> {
    let key = derive_hkdf(cmk, b"vault/v1/index-key")?;
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt(&key, &nonce, REVOCATION_AAD.to_vec(), encode_revocations(revocations))?;
    let mut file = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);
    write_atomic(path, &file)
}

fn encode_revocations(revocations: &[([u8; 32], u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1);
    put_u32(&mut out, revocations.len() as u32);
    for (swarm_id, epoch) in revocations { out.extend_from_slice(swarm_id); put_u64(&mut out, *epoch); }
    out
}

fn decode_revocations(bytes: &[u8]) -> Result<Vec<([u8; 32], u64)>, VaultError> {
    let mut cursor = Cursor::new(bytes);
    if read_u8(&mut cursor)? != 1 { return Err(VaultError::InvalidFormat); }
    let count = read_u32(&mut cursor)? as usize;
    if count > 65_535 { return Err(VaultError::InvalidFormat); }
    let mut revocations = Vec::with_capacity(count);
    for _ in 0..count {
        let mut swarm_id = [0u8; 32];
        cursor.read_exact(&mut swarm_id)?;
        let epoch = read_u64(&mut cursor)?;
        if epoch == 0 { return Err(VaultError::InvalidFormat); }
        revocations.push((swarm_id, epoch));
    }
    if cursor.position() != bytes.len() as u64 || revocations.windows(2).any(|pair| pair[0].0 >= pair[1].0) { return Err(VaultError::InvalidFormat); }
    Ok(revocations)
}

fn rotation_journal_path(root: &Path) -> PathBuf { root.join(ROTATION_JOURNAL_NAME) }
fn rotation_staged_index(root: &Path) -> PathBuf { root.join("index").join("objects.rotate") }
fn rotation_old_index(root: &Path) -> PathBuf { root.join("index").join("objects.old") }
fn rotation_staged_folders(root: &Path) -> PathBuf { root.join("index").join("folders.rotate") }
fn rotation_old_folders(root: &Path) -> PathBuf { root.join("index").join("folders.old") }
fn rotation_staged_revocations(root: &Path) -> PathBuf { root.join("index").join("revocations.rotate") }
fn rotation_old_revocations(root: &Path) -> PathBuf { root.join("index").join("revocations.old") }
fn rotation_staged_identity(root: &Path) -> PathBuf { root.join(".identity.rotate") }
fn rotation_old_identity(root: &Path) -> PathBuf { root.join(".identity.old") }

fn compaction_journal_path(root: &Path) -> PathBuf { root.join(COMPACTION_JOURNAL_NAME) }
fn compaction_staged_index(root: &Path) -> PathBuf { root.join("index").join("objects.compact") }
fn compaction_old_index(root: &Path) -> PathBuf { root.join("index").join("objects.gc-old") }
fn compaction_staged_segment(root: &Path) -> PathBuf { root.join(SEGMENT_DIR).join(format!("{}.compact", SEGMENT_NAME)) }
fn compaction_old_segment(root: &Path) -> PathBuf { root.join(SEGMENT_DIR).join(format!("{}.gc-old", SEGMENT_NAME)) }

fn write_compaction_journal(root: &Path, phase: u8) -> Result<(), VaultError> {
    let mut bytes = Vec::with_capacity(9);
    bytes.extend_from_slice(COMPACTION_MAGIC);
    bytes.push(phase);
    write_atomic(&compaction_journal_path(root), &bytes)
}

fn recover_compaction(root: &Path) -> Result<(), VaultError> {
    let journal_path = compaction_journal_path(root);
    let bytes = match fs::read(&journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(VaultError::Io(error)),
    };
    if bytes.len() != 9 || &bytes[..8] != COMPACTION_MAGIC || !(COMPACTION_PREPARED..=COMPACTION_INDEX_SWAPPED).contains(&bytes[8]) { return Err(VaultError::InvalidFormat); }
    let phase = bytes[8];
    let active_index = root.join(INDEX_DIR);
    let staged_index = compaction_staged_index(root);
    let old_index = compaction_old_index(root);
    let active_segment = root.join(SEGMENT_DIR).join(SEGMENT_NAME);
    let staged_segment = compaction_staged_segment(root);
    let old_segment = compaction_old_segment(root);
    if phase == COMPACTION_INDEX_SWAPPED {
        if staged_index.exists() { fs::remove_dir_all(&staged_index)?; }
        if old_index.exists() { fs::remove_dir_all(&old_index)?; }
        if staged_segment.exists() { fs::remove_file(&staged_segment)?; }
        if old_segment.exists() { fs::remove_file(&old_segment)?; }
    } else {
        if old_index.exists() {
            if active_index.exists() { fs::remove_dir_all(&active_index)?; }
            fs::rename(&old_index, &active_index)?;
        }
        if staged_index.exists() { fs::remove_dir_all(&staged_index)?; }
        if old_segment.exists() {
            if active_segment.exists() { fs::remove_file(&active_segment)?; }
            fs::rename(&old_segment, &active_segment)?;
        }
        if staged_segment.exists() { fs::remove_file(&staged_segment)?; }
    }
    sync_dir(root.join(INDEX_DIR).parent().ok_or(VaultError::InvalidFormat)?)?;
    sync_dir(&root.join(SEGMENT_DIR))?;
    fs::remove_file(journal_path)?;
    sync_dir(root)?;
    Ok(())
}

fn encode_rotation_journal(journal: &RotationJournal) -> Vec<u8> {
    let mut out = Vec::new(); out.extend_from_slice(ROTATION_MAGIC); out.push(journal.phase); put_bytes(&mut out, &journal.old_header); put_bytes(&mut out, &journal.new_header); out
}

fn decode_rotation_journal(bytes: &[u8]) -> Result<RotationJournal, VaultError> {
    let mut cursor = Cursor::new(bytes); let mut magic = [0u8; 8]; cursor.read_exact(&mut magic)?;
    if &magic != ROTATION_MAGIC { return Err(VaultError::InvalidFormat); }
    let phase = read_u8(&mut cursor)?;
    if !(ROTATION_PREPARED..=ROTATION_HEADER_SWAPPED).contains(&phase) { return Err(VaultError::InvalidFormat); }
    let old_header = read_vec(&mut cursor)?; let new_header = read_vec(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 || old_header.is_empty() || new_header.is_empty() { return Err(VaultError::InvalidFormat); }
    Ok(RotationJournal { phase, old_header, new_header })
}

fn write_rotation_journal(root: &Path, journal: &RotationJournal) -> Result<(), VaultError> { write_atomic(&rotation_journal_path(root), &encode_rotation_journal(journal)) }

fn recover_rotation(root: &Path) -> Result<(), VaultError> {
    let journal_path = rotation_journal_path(root);
    let bytes = match fs::read(&journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(VaultError::Io(error)),
    };
    let journal = decode_rotation_journal(&bytes)?;
    let current_header = fs::read(root.join(HEADER_NAME))?;
    let header_is_new = current_header == journal.new_header;
    let header_is_old = current_header == journal.old_header;
    if !header_is_new && !header_is_old { return Err(VaultError::InvalidFormat); }
    let active_index = root.join(INDEX_DIR);
    let staged_index = rotation_staged_index(root);
    let old_index = rotation_old_index(root);
    let active_folders = folder_index_path(root);
    let staged_folders = rotation_staged_folders(root);
    let old_folders = rotation_old_folders(root);
    let active_revocations = revocation_index_path(root);
    let staged_revocations = rotation_staged_revocations(root);
    let old_revocations = rotation_old_revocations(root);
    let active_identity = root.join(IDENTITY_NAME);
    let staged_identity = rotation_staged_identity(root);
    let old_identity = rotation_old_identity(root);
    if header_is_new {
        if old_index.exists() { fs::remove_dir_all(&old_index)?; }
        if staged_index.exists() { fs::remove_dir_all(&staged_index)?; }
        if old_folders.exists() { fs::remove_file(&old_folders)?; }
        if staged_folders.exists() { fs::remove_file(&staged_folders)?; }
        if old_revocations.exists() { fs::remove_file(&old_revocations)?; }
        if staged_revocations.exists() { fs::remove_file(&staged_revocations)?; }
        if old_identity.exists() { fs::remove_file(&old_identity)?; }
        if staged_identity.exists() { fs::remove_file(&staged_identity)?; }
    } else {
        if old_index.exists() {
            if active_index.exists() { fs::remove_dir_all(&active_index)?; }
            fs::rename(&old_index, &active_index)?;
        } else if staged_index.exists() { fs::remove_dir_all(&staged_index)?; }
        if old_folders.exists() {
            if active_folders.exists() { fs::remove_file(&active_folders)?; }
            fs::rename(&old_folders, &active_folders)?;
        } else if staged_folders.exists() {
            fs::remove_file(&staged_folders)?;
        } else if active_folders.exists() {
            fs::remove_file(&active_folders)?;
        }
        if old_revocations.exists() {
            if active_revocations.exists() { fs::remove_file(&active_revocations)?; }
            fs::rename(&old_revocations, &active_revocations)?;
        } else if staged_revocations.exists() {
            fs::remove_file(&staged_revocations)?;
        }
        if old_identity.exists() {
            if active_identity.exists() { fs::remove_file(&active_identity)?; }
            fs::rename(&old_identity, &active_identity)?;
        } else if staged_identity.exists() { fs::remove_file(&staged_identity)?; }
    }
    if let Some(parent) = active_index.parent() { sync_dir(parent)?; }
    sync_dir(root)?;
    fs::remove_file(journal_path)?;
    sync_dir(root)?;
    Ok(())
}

#[derive(Debug)]
struct StoredRecord {
    cek: [u8; KEY_LENGTH],
    manifest_nonce: [u8; NONCE_LENGTH],
    manifest_ciphertext: Vec<u8>,
    locations: Vec<BlockLocation>,
}

impl Drop for StoredRecord {
    fn drop(&mut self) {
        self.cek.zeroize();
        self.manifest_nonce.zeroize();
        self.manifest_ciphertext.zeroize();
    }
}

#[derive(Debug, Clone)]
struct BlockLocation { offset: u64, len: u32 }

#[derive(Debug)]
struct Manifest { name: String, object_id: ObjectId, plaintext_len: u64, block_size: u32, nonce_prefix: [u8; NONCE_PREFIX_LENGTH], block_ids: Vec<[u8; 32]> }

struct ObjectPlaintextReader {
    object_id: ObjectId,
    cek: Zeroizing<[u8; KEY_LENGTH]>,
    manifest: Manifest,
    locations: Vec<BlockLocation>,
    segment: File,
    block_index: usize,
    current: Vec<u8>,
    current_offset: usize,
    remaining: u64,
}

impl ObjectPlaintextReader {
    fn open(container: &Container, id: ObjectId) -> Result<Self, VaultError> {
        let record = container.read_index_record(&container.index_path(&id))?;
        let (info, stored) = decode_index_record(&record)?;
        if info.id != id { return Err(VaultError::Integrity); }
        let manifest_bytes = decrypt(&stored.cek, &stored.manifest_nonce, [MANIFEST_AAD, id.as_bytes()].concat(), &stored.manifest_ciphertext)?;
        let manifest = decode_manifest(&manifest_bytes)?;
        if manifest.object_id != id || manifest.block_ids.len() != stored.locations.len() { return Err(VaultError::Integrity); }
        Ok(Self { object_id: id, cek: Zeroizing::new(stored.cek), manifest, locations: stored.locations.clone(), segment: File::open(container.root.join(SEGMENT_DIR).join(SEGMENT_NAME))?, block_index: 0, current: Vec::new(), current_offset: 0, remaining: info.plaintext_len })
    }

    fn plaintext_len(&self) -> u64 { self.manifest.plaintext_len }

    fn load_next_block(&mut self) -> io::Result<bool> {
        if self.block_index >= self.manifest.block_ids.len() { return Ok(false); }
        let index = self.block_index;
        let ciphertext = read_segment_block(&mut self.segment, &self.locations[index], &self.manifest.block_ids[index]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        let last = index + 1 == self.manifest.block_ids.len();
        let nonce = block_nonce(&self.manifest.nonce_prefix, index as u64, last);
        let aad = block_aad(&self.object_id, index as u64, last, self.manifest.plaintext_len);
        self.current = decrypt(&self.cek, &nonce, aad, &ciphertext).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if self.current.len() as u64 > self.remaining { self.current.truncate(self.remaining as usize); }
        self.current_offset = 0;
        self.remaining = self.remaining.saturating_sub(self.current.len() as u64);
        self.block_index += 1;
        Ok(true)
    }
}

impl Read for ObjectPlaintextReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() { return Ok(0); }
        let mut written = 0;
        while written < output.len() {
            if self.current_offset == self.current.len() {
                self.current.clear();
                self.current_offset = 0;
                if !self.load_next_block()? { break; }
            }
            let available = self.current.len() - self.current_offset;
            let count = available.min(output.len() - written);
            output[written..written + count].copy_from_slice(&self.current[self.current_offset..self.current_offset + count]);
            self.current_offset += count;
            written += count;
        }
        Ok(written)
    }
}

impl Drop for ObjectPlaintextReader {
    fn drop(&mut self) { self.current.zeroize(); }
}

fn read_header(root: &Path) -> Result<Header, VaultError> {
    if !root.is_dir() { return Err(VaultError::NotFound); }
    recover_rotation(root)?;
    recover_compaction(root)?;
    Header::decode(&fs::read(root.join(HEADER_NAME))?)
}

fn decode_header_backup(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let mut cursor = Cursor::new(bytes);
    let mut magic = [0u8; 8];
    cursor.read_exact(&mut magic)?;
    if &magic != BACKUP_MAGIC { return Err(VaultError::InvalidFormat); }
    let header_len = read_u32(&mut cursor)? as usize;
    if header_len == 0 || header_len > MAX_BACKUP_COMPONENT_BYTES { return Err(VaultError::InvalidFormat); }
    let mut header = vec![0u8; header_len];
    cursor.read_exact(&mut header)?;
    Header::decode(&header)?;
    let identity_len = read_u32(&mut cursor)? as usize;
    if identity_len < NONCE_LENGTH + TAG_LENGTH || identity_len > MAX_BACKUP_COMPONENT_BYTES { return Err(VaultError::InvalidFormat); }
    let mut identity = vec![0u8; identity_len];
    cursor.read_exact(&mut identity)?;
    if cursor.position() != bytes.len() as u64 { return Err(VaultError::InvalidFormat); }
    Ok((header, identity))
}

fn recover_segment_tail(root: &Path) -> Result<(), VaultError> {
    let path = root.join(SEGMENT_DIR).join(SEGMENT_NAME);
    let mut segment = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(segment) => segment,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(VaultError::Io(error)),
    };
    let file_len = segment.metadata()?.len();
    let mut offset = 0u64;
    loop {
        if offset == file_len { return Ok(()); }
        segment.seek(SeekFrom::Start(offset))?;
        let mut length_bytes = [0u8; 4];
        if let Err(error) = segment.read_exact(&mut length_bytes) {
            if error.kind() == io::ErrorKind::UnexpectedEof { segment.set_len(offset)?; segment.sync_all()?; return Ok(()); }
            return Err(VaultError::Io(error));
        }
        let length = u32::from_le_bytes(length_bytes) as usize;
        if !(TAG_LENGTH..=MAX_BLOCK_SIZE + TAG_LENGTH).contains(&length) { return Err(VaultError::Integrity); }
        let record_end = offset.checked_add(4 + 32 + length as u64).ok_or(VaultError::Integrity)?;
        if record_end > file_len { segment.set_len(offset)?; segment.sync_all()?; return Ok(()); }
        let mut block_id = [0u8; 32];
        segment.read_exact(&mut block_id)?;
        let mut ciphertext = vec![0u8; length];
        segment.read_exact(&mut ciphertext)?;
        if *blake3::hash(&ciphertext).as_bytes() != block_id { return Err(VaultError::Integrity); }
        offset = record_end;
    }
}

fn acquire_lock(root: &Path) -> Result<File, VaultError> {
    let lock = OpenOptions::new().create(true).read(true).write(true).open(root.join(LOCK_NAME))?;
    lock.try_lock_exclusive().map_err(|_| VaultError::AlreadyOpen)?;
    let mut lock = lock;
    lock.set_len(0)?;
    write!(lock, "{}", instance_id())?;
    lock.sync_all()?;
    Ok(lock)
}

fn delay_after_auth_failure(root: &Path) {
    let failures = AUTH_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut failures) = failures.lock() else { return; };
    let now = Instant::now();
    let entry = failures.entry(root.to_path_buf()).or_insert((now, 0));
    if now.duration_since(entry.0) > AUTH_FAILURE_WINDOW { *entry = (now, 0); }
    let delay = auth_backoff(entry.1);
    entry.1 = entry.1.saturating_add(1);
    drop(failures);
    thread::sleep(delay);
}

fn auth_backoff(attempt: u32) -> Duration {
    Duration::from_millis((AUTH_BACKOFF_BASE_MS << attempt.min(4)).min(AUTH_BACKOFF_MAX_MS))
}

fn clear_auth_failures(root: &Path) {
    if let Some(failures) = AUTH_FAILURES.get() {
        if let Ok(mut failures) = failures.lock() { failures.remove(root); }
    }
}

fn instance_id() -> String {
    let mut random = [0u8; 16]; OsRng.fill_bytes(&mut random);
    format!("{}-{}", std::process::id(), hex(&random))
}

fn slot_aad(kind: u8, kdf: KdfParams, salt: &[u8; SALT_LENGTH]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 2 + 4 + 12 + SALT_LENGTH + 1);
    aad.extend_from_slice(MAGIC); put_u16(&mut aad, FORMAT_VERSION); put_u32(&mut aad, DEFAULT_BLOCK_SIZE as u32); put_u32(&mut aad, kdf.memory_kib); put_u32(&mut aad, kdf.time_cost); put_u32(&mut aad, kdf.parallelism); aad.extend_from_slice(salt); aad.push(kind); aad
}

fn manifest_signing_bytes(manifest_id: &[u8; 32], swarm_id: &[u8; 32], object_id: &[u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 16 + 28);
    bytes.extend_from_slice(b"vault/v1/manifest-signature");
    bytes.extend_from_slice(manifest_id);
    bytes.extend_from_slice(swarm_id);
    bytes.extend_from_slice(object_id);
    bytes
}

fn block_nonce(prefix: &[u8; NONCE_PREFIX_LENGTH], index: u64, last: bool) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH]; nonce[..NONCE_PREFIX_LENGTH].copy_from_slice(prefix); nonce[15..23].copy_from_slice(&index.to_le_bytes()); nonce[23] = u8::from(last); nonce
}

fn block_aad(id: &ObjectId, index: u64, last: bool, plaintext_len: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BLOCK_AAD.len() + 16 + 8 + 1 + 4); aad.extend_from_slice(BLOCK_AAD); aad.extend_from_slice(id.as_bytes()); aad.extend_from_slice(&index.to_le_bytes()); aad.push(u8::from(last)); aad.extend_from_slice(&(plaintext_len as u32).to_le_bytes()); aad
}

fn derive_hkdf(cmk: &[u8; KEY_LENGTH], label: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>, VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(cmk), label); let mut key = Zeroizing::new([0u8; KEY_LENGTH]); hk.expand(&[], key.as_mut()).map_err(|_| VaultError::Crypto)?; Ok(key)
}

fn encrypt(key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: Vec<u8>, mut plaintext: Vec<u8>) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Crypto)?; cipher.encrypt_in_place(XNonce::from_slice(nonce), &aad, &mut plaintext).map_err(|_| VaultError::Crypto)?; Ok(plaintext)
}

fn decrypt(key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: Vec<u8>, ciphertext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Crypto)?; let mut plaintext = ciphertext.to_vec(); cipher.decrypt_in_place(XNonce::from_slice(nonce), &aad, &mut plaintext).map_err(|_| VaultError::Integrity)?; Ok(plaintext)
}

fn password_material(password: &[u8], keyfile: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut material = Zeroizing::new(password.to_vec());
    if let Some(keyfile) = keyfile {
        if keyfile.is_empty() || keyfile.len() > MAX_KEYFILE_BYTES { return Err(VaultError::UnlockFailed); }
        material.extend_from_slice(blake3::hash(keyfile).as_bytes());
    }
    Ok(material)
}

pub fn inspect_encrypted_manifest(id: ObjectId, expected_manifest_id: [u8; 32], cek: [u8; 32], manifest_nonce: [u8; 24], manifest_ciphertext: &[u8]) -> Result<EncryptedManifest, VaultError> {
    if manifest_ciphertext.len() < TAG_LENGTH || manifest_ciphertext.len() > 64 * 1024 * 1024 || *blake3::hash(manifest_ciphertext).as_bytes() != expected_manifest_id { return Err(VaultError::Integrity); }
    let bytes = decrypt(&cek, &manifest_nonce, [MANIFEST_AAD, id.as_bytes()].concat(), manifest_ciphertext)?;
    let manifest = decode_manifest(&bytes)?;
    if manifest.object_id != id { return Err(VaultError::Integrity); }
    Ok(EncryptedManifest { name: manifest.name, plaintext_len: manifest.plaintext_len, block_size: manifest.block_size, nonce_prefix: manifest.nonce_prefix, block_ids: manifest.block_ids })
}

fn read_segment_block<R: Read + Seek>(segment: &mut R, location: &BlockLocation, expected_id: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    segment.seek(SeekFrom::Start(location.offset))?;
    let len = read_u32(segment)? as usize;
    if len != location.len as usize || len < TAG_LENGTH || len > MAX_BLOCK_SIZE + TAG_LENGTH { return Err(VaultError::Integrity); }
    let mut stored_id = [0u8; 32]; segment.read_exact(&mut stored_id)?;
    let mut ciphertext = vec![0u8; len]; segment.read_exact(&mut ciphertext)?;
    if &stored_id != expected_id || *blake3::hash(&ciphertext).as_bytes() != *expected_id { return Err(VaultError::Integrity); }
    Ok(ciphertext)
}

fn encode_manifest(name: &str, id: &ObjectId, plaintext_len: u64, block_size: u32, nonce_prefix: &[u8; NONCE_PREFIX_LENGTH], block_ids: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::new(); put_bytes(&mut out, name.as_bytes()); out.extend_from_slice(id.as_bytes()); put_u64(&mut out, plaintext_len); put_u32(&mut out, block_size); out.extend_from_slice(nonce_prefix); put_u32(&mut out, block_ids.len() as u32); for id in block_ids { out.extend_from_slice(id); } let mut root_input = Vec::with_capacity(block_ids.len() * 32 + 12); for id in block_ids { root_input.extend_from_slice(id); } root_input.extend_from_slice(&plaintext_len.to_le_bytes()); root_input.extend_from_slice(&block_size.to_le_bytes()); out.extend_from_slice(blake3::hash(&root_input).as_bytes()); out
}

fn decode_manifest(bytes: &[u8]) -> Result<Manifest, VaultError> {
    let mut c = Cursor::new(bytes); let name = String::from_utf8(read_vec(&mut c)?).map_err(|_| VaultError::InvalidFormat)?; validate_name(&name)?; let mut object_id = [0u8; 16]; c.read_exact(&mut object_id)?; let plaintext_len = read_u64(&mut c)?; if plaintext_len > u32::MAX as u64 { return Err(VaultError::FileTooLarge); } let block_size = read_u32(&mut c)?; if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&(block_size as usize)) { return Err(VaultError::InvalidBlockSize); } let mut nonce_prefix = [0u8; NONCE_PREFIX_LENGTH]; c.read_exact(&mut nonce_prefix)?; let count = read_u32(&mut c)? as usize; if count == 0 || count > 4 * 1024 * 1024 { return Err(VaultError::InvalidFormat); } let mut block_ids = Vec::with_capacity(count); for _ in 0..count { let mut id = [0u8; 32]; c.read_exact(&mut id)?; block_ids.push(id); } let mut integrity_root = [0u8; 32]; c.read_exact(&mut integrity_root)?; if c.position() != bytes.len() as u64 { return Err(VaultError::InvalidFormat); } let mut root_input = Vec::with_capacity(count * 32 + 12); for id in &block_ids { root_input.extend_from_slice(id); } root_input.extend_from_slice(&plaintext_len.to_le_bytes()); root_input.extend_from_slice(&block_size.to_le_bytes()); if *blake3::hash(&root_input).as_bytes() != integrity_root { return Err(VaultError::Integrity); } Ok(Manifest { name, object_id: ObjectId(object_id), plaintext_len, block_size, nonce_prefix, block_ids })
}

fn encode_index_record(name: &str, id: &ObjectId, plaintext_len: u64, block_size: u32, cek: &[u8; KEY_LENGTH], manifest_nonce: &[u8; NONCE_LENGTH], manifest_ciphertext: &[u8], block_ids: &[[u8; 32]], locations: &[BlockLocation]) -> Result<Vec<u8>, VaultError> {
    if block_ids.len() != locations.len() { return Err(VaultError::InvalidFormat); }
    let mut out = Vec::new(); put_bytes(&mut out, name.as_bytes()); out.extend_from_slice(id.as_bytes()); put_u64(&mut out, plaintext_len); put_u32(&mut out, block_size); out.extend_from_slice(cek); out.extend_from_slice(manifest_nonce); put_bytes(&mut out, manifest_ciphertext); put_u32(&mut out, locations.len() as u32); for (block_id, location) in block_ids.iter().zip(locations) { out.extend_from_slice(block_id); put_u64(&mut out, location.offset); put_u32(&mut out, location.len); } Ok(out)
}

fn encode_transfer_checkpoint(id: ObjectId, checkpoint: &TransferCheckpoint) -> Result<Vec<u8>, VaultError> {
    let mut out = Vec::new();
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&checkpoint.cek);
    out.extend_from_slice(&checkpoint.manifest_id);
    out.extend_from_slice(&checkpoint.manifest_nonce);
    put_bytes(&mut out, &checkpoint.manifest_ciphertext);
    put_u32(&mut out, checkpoint.blocks.len() as u32);
    for block in &checkpoint.blocks {
        out.extend_from_slice(&block.id);
        put_bytes(&mut out, &block.bytes);
    }
    Ok(out)
}

fn decode_transfer_checkpoint(id: ObjectId, bytes: &[u8]) -> Result<TransferCheckpoint, VaultError> {
    let mut cursor = Cursor::new(bytes);
    let mut stored_id = [0u8; 16]; cursor.read_exact(&mut stored_id)?;
    if stored_id != *id.as_bytes() { return Err(VaultError::Integrity); }
    let mut cek = [0u8; KEY_LENGTH]; cursor.read_exact(&mut cek)?;
    let mut manifest_id = [0u8; 32]; cursor.read_exact(&mut manifest_id)?;
    let mut manifest_nonce = [0u8; NONCE_LENGTH]; cursor.read_exact(&mut manifest_nonce)?;
    let manifest_ciphertext = read_vec(&mut cursor)?;
    let count = read_u32(&mut cursor)? as usize;
    if count > 4 * 1024 * 1024 { return Err(VaultError::Integrity); }
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let mut block_id = [0u8; 32]; cursor.read_exact(&mut block_id)?;
        let block_bytes = read_vec(&mut cursor)?;
        if block_bytes.len() < TAG_LENGTH || block_bytes.len() > MAX_BLOCK_SIZE + TAG_LENGTH { return Err(VaultError::Integrity); }
        blocks.push(EncryptedBlock { id: block_id, bytes: block_bytes });
    }
    if cursor.position() != bytes.len() as u64 { return Err(VaultError::Integrity); }
    Ok(TransferCheckpoint { cek, manifest_id, manifest_nonce, manifest_ciphertext, blocks })
}

fn decode_index_record(bytes: &[u8]) -> Result<(ObjectInfo, StoredRecord), VaultError> {
    let mut c = Cursor::new(bytes); let name = String::from_utf8(read_vec(&mut c)?).map_err(|_| VaultError::InvalidFormat)?; let mut object_id = [0u8; 16]; c.read_exact(&mut object_id)?; let plaintext_len = read_u64(&mut c)?; let block_size = read_u32(&mut c)?; if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&(block_size as usize)) { return Err(VaultError::InvalidFormat); } let mut cek = [0u8; KEY_LENGTH]; c.read_exact(&mut cek)?; let mut manifest_nonce = [0u8; NONCE_LENGTH]; c.read_exact(&mut manifest_nonce)?; let manifest_ciphertext = read_vec(&mut c)?; let count = read_u32(&mut c)? as usize; if count == 0 || count > 4 * 1024 * 1024 { return Err(VaultError::InvalidFormat); } let mut locations = Vec::with_capacity(count); for _ in 0..count { let mut block_id = [0u8; 32]; c.read_exact(&mut block_id)?; let offset = read_u64(&mut c)?; let len = read_u32(&mut c)?; if len < TAG_LENGTH as u32 { return Err(VaultError::InvalidFormat); } locations.push(BlockLocation { offset, len }); } if c.position() != bytes.len() as u64 { return Err(VaultError::InvalidFormat); } Ok((ObjectInfo { id: ObjectId(object_id), name, plaintext_len, block_count: count }, StoredRecord { cek, manifest_nonce, manifest_ciphertext, locations }))
}

fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty() || name.len() > 4096 || name.starts_with('/') || name.ends_with('/') || name.contains('\0') || name.contains('\\') || name.split('/').any(|part| part.is_empty() || part == "." || part == "..") { return Err(VaultError::InvalidFormat); }
    Ok(())
}

fn replace_path_prefix(path: &str, old_prefix: &str, new_prefix: &str) -> String {
    if path == old_prefix { new_prefix.to_owned() } else { format!("{}{}", new_prefix, &path[old_prefix.len()..]) }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let mut suffix = [0u8; 8]; OsRng.fill_bytes(&mut suffix); let temp = path.with_file_name(format!(".{}.{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("vault"), hex(&suffix))); let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)?; file.write_all(bytes)?; file.sync_all()?; drop(file); fs::rename(&temp, path)?; if let Some(parent) = path.parent() { sync_dir(parent)?; } Ok(())
}

fn sync_dir(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    { File::open(path)?.sync_all()?; }
    #[cfg(windows)]
    { let _ = path; }
    Ok(())
}

fn read_vec<R: Read>(reader: &mut R) -> Result<Vec<u8>, VaultError> { let len = read_u32(reader)? as usize; if len > 64 * 1024 * 1024 { return Err(VaultError::InvalidFormat); } let mut bytes = vec![0u8; len]; reader.read_exact(&mut bytes)?; Ok(bytes) }
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) { put_u32(out, bytes.len() as u32); out.extend_from_slice(bytes); }
fn put_u16(out: &mut Vec<u8>, value: u16) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_u32_to_writer<W: Write>(writer: &mut W, value: u32) -> Result<(), VaultError> { writer.write_all(&value.to_le_bytes())?; Ok(()) }
fn read_u8<R: Read>(reader: &mut R) -> Result<u8, VaultError> { let mut bytes = [0u8; 1]; reader.read_exact(&mut bytes)?; Ok(bytes[0]) }
fn read_u16<R: Read>(reader: &mut R) -> Result<u16, VaultError> { let mut bytes = [0u8; 2]; reader.read_exact(&mut bytes)?; Ok(u16::from_le_bytes(bytes)) }
fn read_u32<R: Read>(reader: &mut R) -> Result<u32, VaultError> { let mut bytes = [0u8; 4]; reader.read_exact(&mut bytes)?; Ok(u32::from_le_bytes(bytes)) }
fn read_u64<R: Read>(reader: &mut R) -> Result<u64, VaultError> { let mut bytes = [0u8; 8]; reader.read_exact(&mut bytes)?; Ok(u64::from_le_bytes(bytes)) }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn decode_hex_16(value: &str) -> Result<[u8; 16], VaultError> {
    if value.len() != 32 { return Err(VaultError::InvalidFormat); }
    let mut bytes = [0u8; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).ok_or(VaultError::InvalidFormat)? as u8;
        let low = (pair[1] as char).to_digit(16).ok_or(VaultError::InvalidFormat)? as u8;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

pub fn encode_recovery_key(raw: &[u8; KEY_LENGTH]) -> String {
    let mut bytes = Vec::with_capacity(KEY_LENGTH + 2); bytes.extend_from_slice(raw); bytes.extend_from_slice(&blake3::hash(raw).as_bytes()[..2]); let encoded = base32_encode(&bytes); encoded.as_bytes().chunks(5).map(|chunk| std::str::from_utf8(chunk).unwrap()).collect::<Vec<_>>().join("-")
}

fn decode_recovery_key(value: &str) -> Result<[u8; KEY_LENGTH], VaultError> {
    let normalized: String = value.chars().filter(|char| *char != '-').collect(); let bytes = base32_decode(&normalized)?; if bytes.len() != KEY_LENGTH + 2 || blake3::hash(&bytes[..KEY_LENGTH]).as_bytes()[..2] != bytes[KEY_LENGTH..] { return Err(VaultError::InvalidRecoveryKey); } bytes[..KEY_LENGTH].try_into().map_err(|_| VaultError::InvalidRecoveryKey)
}

fn base32_encode(bytes: &[u8]) -> String { let mut output = String::new(); let mut buffer = 0u16; let mut bits = 0u8; for byte in bytes { buffer = (buffer << 8) | *byte as u16; bits += 8; while bits >= 5 { bits -= 5; output.push(BASE32_ALPHABET[((buffer >> bits) & 31) as usize] as char); } } if bits > 0 { output.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char); } output }
fn base32_decode(value: &str) -> Result<Vec<u8>, VaultError> { let mut output = Vec::new(); let mut buffer = 0u32; let mut bits = 0u8; for byte in value.bytes() { let value = match byte.to_ascii_uppercase() { b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A', b'2'..=b'7' => byte - b'2' + 26, _ => return Err(VaultError::InvalidRecoveryKey) } as u32; buffer = (buffer << 5) | value; bits += 5; if bits >= 8 { bits -= 8; output.push((buffer >> bits) as u8); buffer &= (1 << bits) - 1; } } if bits >= 5 || (bits > 0 && buffer != 0) { return Err(VaultError::InvalidRecoveryKey); } Ok(output) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, thread, time::Duration};
    use tempfile::tempdir;

    #[test]
    fn recovery_key_round_trips() {
        let raw = [42u8; KEY_LENGTH]; let encoded = encode_recovery_key(&raw); let decoded = decode_recovery_key(&encoded).unwrap(); assert_eq!(decoded, raw); assert!(decode_recovery_key(&format!("{}A", &encoded[..encoded.len() - 1])).is_err());
    }

    #[test]
    fn authentication_backoff_is_bounded_and_exponential() {
        assert_eq!(auth_backoff(0), Duration::from_millis(250));
        assert_eq!(auth_backoff(1), Duration::from_millis(500));
        assert_eq!(auth_backoff(4), Duration::from_secs(4));
        assert_eq!(auth_backoff(99), Duration::from_secs(4));
    }

    #[test]
    fn create_import_export_and_recover() {
        let dir = tempdir().unwrap(); let path = dir.path().join("personal.vault"); let (container, recovery) = Container::create(&path, b"correct horse battery staple").unwrap(); let source = b"secret bytes never written as plaintext"; let object = container.import_bytes("notes.txt", source).unwrap(); assert_eq!(container.export_bytes(object.id).unwrap(), source); drop(container); let recovered = Container::open_with_recovery(&path, &recovery).unwrap(); assert_eq!(recovered.export_bytes(object.id).unwrap(), source); assert_eq!(recovered.list_objects().unwrap()[0].name, "notes.txt"); drop(recovered); let disk = fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()).collect::<Vec<_>>(); assert!(disk.iter().any(|path| path.ends_with("header.bin"))); assert_no_plaintext(&path, &[source, b"notes.txt", recovery.as_bytes()]); }

    #[test]
    fn encrypted_object_round_trips_without_plaintext_transfer() {
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("source.vault");
        let target_path = dir.path().join("target.vault");
        let (source_container, _) = Container::create(&source_path, b"a long enough password").unwrap();
        let object = source_container.import_bytes("photo.png", b"encrypted object bytes").unwrap();
        let material = source_container.share_material(object.id).unwrap();
        let encrypted = source_container.read_encrypted_object(object.id).unwrap();
        let (target_container, _) = Container::create(&target_path, b"another long password").unwrap();
        target_container.import_encrypted_object(object.id, encrypted.manifest_id, material.cek, encrypted.manifest_nonce, &encrypted.manifest_ciphertext, &encrypted.blocks).unwrap();
        assert_eq!(target_container.export_bytes(object.id).unwrap(), b"encrypted object bytes");
        assert_no_plaintext(&target_path, &[b"encrypted object bytes", b"photo.png"]);
    }

    #[test]
    fn tampered_encrypted_transfer_is_rejected_before_commit() {
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("source.vault");
        let target_path = dir.path().join("target.vault");
        let (source_container, _) = Container::create(&source_path, b"a long enough password").unwrap();
        let object = source_container.import_bytes("payload.bin", b"ciphertext transfer").unwrap();
        let material = source_container.share_material(object.id).unwrap();
        let mut encrypted = source_container.read_encrypted_object(object.id).unwrap();
        encrypted.blocks[0].bytes[0] ^= 1;
        let (target_container, _) = Container::create(&target_path, b"another long password").unwrap();
        assert!(matches!(target_container.import_encrypted_object(object.id, encrypted.manifest_id, material.cek, encrypted.manifest_nonce, &encrypted.manifest_ciphertext, &encrypted.blocks), Err(VaultError::Integrity)));
        assert!(target_container.list_objects().unwrap().is_empty());
    }

    #[test]
    fn encrypted_transfer_checkpoint_round_trips_and_clears() {
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("checkpoint-source.vault");
        let target_path = dir.path().join("checkpoint-target.vault");
        let (source, _) = Container::create(&source_path, b"source long password").unwrap();
        let object = source.import_bytes("large.bin", &vec![7u8; 1_100_000]).unwrap();
        let material = source.share_material(object.id).unwrap();
        let encrypted = source.read_encrypted_object(object.id).unwrap();
        assert!(encrypted.blocks.len() > 1);
        let (target, _) = Container::create(&target_path, b"target long password").unwrap();
        target.save_transfer_checkpoint(object.id, &TransferCheckpoint { cek: material.cek, manifest_id: encrypted.manifest_id, manifest_nonce: encrypted.manifest_nonce, manifest_ciphertext: encrypted.manifest_ciphertext.clone(), blocks: encrypted.blocks[..1].to_vec() }).unwrap();
        let checkpoint = target.load_transfer_checkpoint(object.id).unwrap().unwrap();
        assert_eq!(checkpoint.blocks.len(), 1);
        assert_eq!(checkpoint.manifest_id, encrypted.manifest_id);
        target.clear_transfer_checkpoint(object.id).unwrap();
        assert!(target.load_transfer_checkpoint(object.id).unwrap().is_none());
    }

    #[test]
    fn wrong_password_and_duplicate_open_fail_closed() {
        let dir = tempdir().unwrap(); let path = dir.path().join("locked.vault"); let (container, _) = Container::create(&path, b"a long enough password").unwrap(); assert!(matches!(Container::open(&path, b"wrong password"), Err(VaultError::UnlockFailed))); assert!(matches!(Container::open(&path, b"a long enough password"), Err(VaultError::AlreadyOpen))); drop(container); }

    #[test]
    fn keyfile_is_required_and_survives_password_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keyfile.vault");
        let keyfile = b"local key material";
        let (mut container, recovery) = Container::create_with_keyfile(&path, b"a long enough password", keyfile).unwrap();
        let object = container.import_bytes("keyed.txt", b"keyfile protected").unwrap();
        container.change_password_with_keyfile(b"another long password", keyfile).unwrap();
        container.rotate_cmk_with_keyfile(b"another long password", &recovery, keyfile).unwrap();
        drop(container);
        assert!(matches!(Container::open(&path, b"another long password"), Err(VaultError::UnlockFailed)));
        assert!(matches!(Container::open_with_keyfile(&path, b"a long enough password", keyfile), Err(VaultError::UnlockFailed)));
        let reopened = Container::open_with_keyfile(&path, b"another long password", keyfile).unwrap();
        assert_eq!(reopened.export_bytes(object.id).unwrap(), b"keyfile protected");
        drop(reopened);
        let recovered = Container::open_with_recovery(&path, &recovery).unwrap();
        assert_eq!(recovered.export_bytes(object.id).unwrap(), b"keyfile protected");
    }

    #[test]
    fn tampered_block_is_rejected() {
        let dir = tempdir().unwrap(); let path = dir.path().join("tampered.vault"); let (container, _) = Container::create(&path, b"a long enough password").unwrap(); let _object = container.import_bytes("payload.bin", b"payload").unwrap(); drop(container); let segment = path.join(SEGMENT_DIR).join(SEGMENT_NAME); let mut bytes = fs::read(&segment).unwrap(); let last = bytes.len() - 1; bytes[last] ^= 1; fs::write(&segment, bytes).unwrap(); assert!(matches!(Container::open(&path, b"a long enough password"), Err(VaultError::Integrity))); }

    #[test]
    fn partial_segment_tail_is_truncated_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("partial-segment.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        let segment = path.join(SEGMENT_DIR).join(SEGMENT_NAME);
        drop(container);
        let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        file.sync_all().unwrap();
        let reopened = Container::open(&path, b"a long enough password").unwrap();
        drop(reopened);
        assert_eq!(fs::metadata(segment).unwrap().len(), 0);
    }

    #[test]
    fn header_backup_restores_header_and_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("backup.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        let backup = container.export_header_backup().unwrap();
        drop(container);
        fs::remove_file(path.join(HEADER_NAME)).unwrap();
        fs::remove_file(path.join(IDENTITY_NAME)).unwrap();
        Container::restore_header_backup(&path, &backup).unwrap();
        let restored = Container::open(&path, b"a long enough password").unwrap();
        assert!(restored.identity().public().signing_public.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn revocation_epochs_survive_cmk_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("revocations.vault");
        let (mut container, recovery) = Container::create(&path, b"a long enough password").unwrap();
        let swarm = [7u8; 32];
        assert_eq!(container.revoked_epoch(swarm).unwrap(), 0);
        assert_eq!(container.revoke_swarm(swarm).unwrap(), 1);
        assert_eq!(container.revoke_swarm(swarm).unwrap(), 2);
        container.rotate_cmk(b"a long enough password", &recovery).unwrap();
        assert_eq!(container.revoked_epoch(swarm).unwrap(), 2);
    }

    #[test]
    fn a_stream_length_mismatch_does_not_commit_index() {
        let dir = tempdir().unwrap(); let path = dir.path().join("stream.vault"); let (container, _) = Container::create(&path, b"a long enough password").unwrap(); let result = container.import_reader("broken", 10, Cursor::new(b"short")); assert!(matches!(result, Err(VaultError::LengthMismatch))); assert!(container.list_objects().unwrap().is_empty()); }

    #[test]
    fn lock_is_released_on_drop() {
        let dir = tempdir().unwrap(); let path = dir.path().join("lock.vault"); let (container, _) = Container::create(&path, b"a long enough password").unwrap(); let path_for_thread = path.clone(); let handle = thread::spawn(move || { thread::sleep(Duration::from_millis(10)); assert!(matches!(Container::open(&path_for_thread, b"a long enough password"), Err(VaultError::AlreadyOpen))); }); handle.join().unwrap(); drop(container); assert!(Container::open(&path, b"a long enough password").is_ok()); }

    fn assert_no_plaintext(root: &std::path::Path, needles: &[&[u8]]) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() { assert_no_plaintext(&path, needles); continue; }
            let bytes = fs::read(path).unwrap();
            for needle in needles { assert!(!bytes.windows(needle.len()).any(|window| window == *needle)); }
        }
    }

    #[test]
    fn container_identity_survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        let public = container.identity().public();
        drop(container);
        let reopened = Container::open(&path, b"a long enough password").unwrap();
        assert_eq!(reopened.identity().public(), public);
    }

    #[test]
    fn rename_and_delete_only_change_index_references() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("index.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        let object = container.import_bytes("old.txt", b"stable blocks").unwrap();
        let segment_before = fs::read(path.join(SEGMENT_DIR).join(SEGMENT_NAME)).unwrap();
        let renamed = container.rename_object(object.id, "nested/new.txt").unwrap();
        assert_eq!(renamed.name, "nested/new.txt");
        assert_eq!(container.export_bytes(object.id).unwrap(), b"stable blocks");
        assert_eq!(fs::read(path.join(SEGMENT_DIR).join(SEGMENT_NAME)).unwrap(), segment_before);
        container.delete_object(object.id).unwrap();
        assert!(container.list_objects().unwrap().is_empty());
        assert!(matches!(container.delete_object(object.id), Err(VaultError::NotFound)));
    }

    #[test]
    fn compaction_removes_orphaned_blocks_without_losing_live_objects() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("compact.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        let deleted = container.import_bytes("deleted.bin", &vec![1u8; 1_100_000]).unwrap();
        let live = container.import_bytes("live.bin", b"kept").unwrap();
        let segment = path.join(SEGMENT_DIR).join(SEGMENT_NAME);
        let before = fs::metadata(&segment).unwrap().len();
        container.delete_object(deleted.id).unwrap();
        container.compact().unwrap();
        let after = fs::metadata(segment).unwrap().len();
        assert!(after < before);
        assert_eq!(container.export_bytes(live.id).unwrap(), b"kept");
        assert!(container.list_objects().unwrap().iter().all(|object| object.id == live.id));
        assert!(!path.join(COMPACTION_JOURNAL_NAME).exists());
    }

    #[test]
    fn copy_object_streams_into_a_new_encrypted_object() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("copy.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        let source = container.import_bytes("source.bin", &vec![4u8; 1_100_000]).unwrap();
        let copy = container.copy_object(source.id, "copies/target.bin").unwrap();
        assert_ne!(source.id.as_bytes(), copy.id.as_bytes());
        assert_eq!(container.export_bytes(copy.id).unwrap(), vec![4u8; 1_100_000]);
        assert_no_plaintext(&path, &[&[4u8; 1_100_000][..], b"source.bin", b"copies/target.bin"]);
    }

    #[test]
    fn password_and_recovery_rotation_keep_the_cmk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rotation.vault");
        let (mut container, old_recovery) = Container::create(&path, b"old long password").unwrap();
        let object = container.import_bytes("secret.txt", b"still protected").unwrap();
        container.change_password(b"new long password").unwrap();
        let new_recovery = container.rotate_recovery_key().unwrap();
        drop(container);
        assert!(matches!(Container::open(&path, b"old long password"), Err(VaultError::UnlockFailed)));
        let reopened = Container::open(&path, b"new long password").unwrap();
        assert_eq!(reopened.export_bytes(object.id).unwrap(), b"still protected");
        drop(reopened);
        assert!(matches!(Container::open_with_recovery(&path, &old_recovery), Err(VaultError::UnlockFailed)));
        let recovered = Container::open_with_recovery(&path, &new_recovery).unwrap();
        assert_eq!(recovered.export_bytes(object.id).unwrap(), b"still protected");
    }

    #[test]
    fn cmk_rotation_reencrypts_index_and_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cmk-rotation.vault");
        let (mut container, recovery) = Container::create(&path, b"old long password").unwrap();
        let object = container.import_bytes("secret.txt", b"still protected").unwrap();
        container.create_folder("empty").unwrap();
        let public = container.identity().public();
        container.rotate_cmk(b"new long password", &recovery).unwrap();
        assert_eq!(container.export_bytes(object.id).unwrap(), b"still protected");
        assert_eq!(container.list_folders().unwrap(), vec!["empty".to_owned()]);
        drop(container);

        assert!(matches!(Container::open(&path, b"old long password"), Err(VaultError::UnlockFailed)));
        let reopened = Container::open(&path, b"new long password").unwrap();
        assert_eq!(reopened.identity().public(), public);
        assert_eq!(reopened.export_bytes(object.id).unwrap(), b"still protected");
        drop(reopened);
        let recovered = Container::open_with_recovery(&path, &recovery).unwrap();
        assert_eq!(recovered.export_bytes(object.id).unwrap(), b"still protected");
        assert!(!path.join(ROTATION_JOURNAL_NAME).exists());
    }

    #[test]
    fn virtual_folders_are_encrypted_and_non_destructive() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("folders.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        assert_eq!(container.create_folder("projects/archive").unwrap(), vec!["projects".to_owned(), "projects/archive".to_owned()]);
        let object = container.import_bytes("projects/archive/notes.txt", b"nested").unwrap();
        assert_eq!(container.rename_folder("projects", "renamed").unwrap(), vec!["renamed".to_owned(), "renamed/archive".to_owned()]);
        assert_eq!(container.export_bytes(object.id).unwrap(), b"nested");
        assert_eq!(container.list_objects().unwrap()[0].name, "renamed/archive/notes.txt");
        assert_eq!(container.delete_folder("renamed").unwrap(), Vec::<String>::new());
        assert!(container.list_folders().unwrap().is_empty());
        assert!(container.list_objects().unwrap().is_empty());
    }

    #[test]
    fn opening_recovers_a_prepared_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prepared-rotation.vault");
        let (container, _) = Container::create(&path, b"a long enough password").unwrap();
        let object = container.import_bytes("recovered.txt", b"recovered").unwrap();
        drop(container);

        let active = path.join(INDEX_DIR);
        let old = rotation_old_index(&path);
        fs::rename(&active, &old).unwrap();
        fs::create_dir_all(&active).unwrap();
        let old_header = fs::read(path.join(HEADER_NAME)).unwrap();
        write_rotation_journal(&path, &RotationJournal { phase: ROTATION_PREPARED, old_header, new_header: vec![1] }).unwrap();

        let recovered = Container::open(&path, b"a long enough password").unwrap();
        assert_eq!(recovered.export_bytes(object.id).unwrap(), b"recovered");
        assert!(!old.exists());
        assert!(!path.join(ROTATION_JOURNAL_NAME).exists());
    }
}
