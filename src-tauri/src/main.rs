use std::{collections::HashMap, fs::{self, File}, io::Read, path::PathBuf, sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};
use image::ImageFormat;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use tauri::State;
use vault_core::{Container, ObjectId, ObjectInfo};
use vault_discovery::{derive_discovery_id, DiscoveryRecord, RendezvousClient, RendezvousClientConfig, MAX_TTL_SECONDS};
use vault_identity::{ContactCard, ParticipationKey};
use vault_protocol::{permission, Capability};
use vault_sharing::{Invitation, InvitationPayload};
use vault_transfer::{DownloadSession, Seeder};
use vault_transport::RelayConfig;
use zeroize::Zeroizing;

struct VaultState(Mutex<ContainerStore>, Mutex<Vec<SeedHandle>>);
const MAX_KEYFILE_BYTES: usize = 1024 * 1024;

struct SeedHandle {
    cancel: Arc<AtomicBool>,
    swarm_id: [u8; 32],
    revoked_epoch: Arc<AtomicU64>,
}

#[derive(Default)]
struct ContainerStore {
    active: Option<PathBuf>,
    containers: HashMap<PathBuf, Container>,
}

impl ContainerStore {
    fn activate(&mut self, path: PathBuf) -> Result<(), String> {
        if !self.containers.contains_key(&path) { return Err("container não está aberto".to_owned()); }
        self.active = Some(path);
        Ok(())
    }

    fn insert_active(&mut self, path: PathBuf, container: Container) {
        self.containers.insert(path.clone(), container);
        self.active = Some(path);
    }

    fn active(&self) -> Result<&Container, String> {
        let path = self.active.as_ref().ok_or_else(|| "container está bloqueado".to_owned())?;
        self.containers.get(path).ok_or_else(|| "container está bloqueado".to_owned())
    }

    fn active_mut(&mut self) -> Result<&mut Container, String> {
        let path = self.active.as_ref().ok_or_else(|| "container está bloqueado".to_owned())?.clone();
        self.containers.get_mut(&path).ok_or_else(|| "container está bloqueado".to_owned())
    }

    fn close_active(&mut self) {
        if let Some(path) = self.active.take() { self.containers.remove(&path); }
    }
}

#[derive(Debug, Serialize)]
struct ObjectSummary {
    id: String,
    name: String,
    plaintext_len: u64,
    block_count: usize,
}

#[derive(Debug, Serialize)]
struct ImagePreview {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct ContactSummary {
    name: String,
    signing_public: Vec<u8>,
    hpke_public: Vec<u8>,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct InvitationSummary {
    object_id: String,
    swarm_id: String,
    owner_fingerprint: String,
    permissions: u32,
    expires: u64,
    relay_hints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CreatedInvitation {
    invitation: String,
    object_id: String,
    swarm_id: String,
    relay_hints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiscoverySourceSummary {
    relay_endpoint: String,
    expires_at: u64,
}

fn summarize(object: ObjectInfo) -> ObjectSummary {
    ObjectSummary { id: hex(object.id.as_bytes()), name: object.name, plaintext_len: object.plaintext_len, block_count: object.block_count }
}

fn cancel_seeders(state: &VaultState) {
    if let Ok(seed_flags) = state.1.lock() {
        for seed in seed_flags.iter() { seed.cancel.store(false, Ordering::Release); }
    }
}

#[tauri::command]
fn create_container(state: State<'_, VaultState>, path: String, password: String, keyfile_path: Option<String>) -> Result<String, String> {
    let path = PathBuf::from(path);
    let keyfile = read_keyfile(keyfile_path)?;
    let result = match keyfile.as_deref() {
        Some(keyfile) => Container::create_with_keyfile(&path, password.as_bytes(), keyfile),
        None => Container::create(&path, password.as_bytes()),
    };
    let (container, recovery_key) = result.map_err(|error| error.to_string())?;
    cancel_seeders(state.inner());
    state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?.insert_active(path, container);
    Ok(recovery_key)
}

#[tauri::command]
fn unlock_container(state: State<'_, VaultState>, path: String, password: String, keyfile_path: Option<String>) -> Result<Vec<ObjectSummary>, String> {
    let path = PathBuf::from(path);
    let keyfile = read_keyfile(keyfile_path)?;
    let result = match keyfile.as_deref() {
        Some(keyfile) => Container::open_with_keyfile(&path, password.as_bytes(), keyfile),
        None => Container::open(&path, password.as_bytes()),
    };
    let container = result.map_err(|error| error.to_string())?;
    let objects = container.list_objects().map_err(|error| error.to_string())?.into_iter().map(summarize).collect();
    cancel_seeders(state.inner());
    state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?.insert_active(path, container);
    Ok(objects)
}

#[tauri::command]
fn unlock_container_recovery(state: State<'_, VaultState>, path: String, recovery_key: String) -> Result<Vec<ObjectSummary>, String> {
    let path = PathBuf::from(path);
    let container = Container::open_with_recovery(&path, &recovery_key).map_err(|error| error.to_string())?;
    let objects = container.list_objects().map_err(|error| error.to_string())?.into_iter().map(summarize).collect();
    cancel_seeders(state.inner());
    state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?.insert_active(path, container);
    Ok(objects)
}

#[tauri::command]
fn lock_container(state: State<'_, VaultState>) -> Result<(), String> {
    cancel_seeders(state.inner());
    state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?.close_active();
    Ok(())
}

#[tauri::command]
fn activate_container(state: State<'_, VaultState>, path: String) -> Result<(), String> {
    state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?.activate(PathBuf::from(path))
}

#[tauri::command]
fn list_objects(state: State<'_, VaultState>) -> Result<Vec<ObjectSummary>, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    Ok(container.list_objects().map_err(|error| error.to_string())?.into_iter().map(summarize).collect())
}

#[tauri::command]
fn rename_object(state: State<'_, VaultState>, object_id: String, name: String) -> Result<ObjectSummary, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    Ok(summarize(container.rename_object(parse_object_id(&object_id)?, &name).map_err(|error| error.to_string())?))
}

#[tauri::command]
fn copy_object(state: State<'_, VaultState>, object_id: String, name: String) -> Result<ObjectSummary, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    Ok(summarize(container.copy_object(parse_object_id(&object_id)?, &name).map_err(|error| error.to_string())?))
}

#[tauri::command]
fn delete_object(state: State<'_, VaultState>, object_id: String) -> Result<(), String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    container.delete_object(parse_object_id(&object_id)?).map_err(|error| error.to_string())
}

#[tauri::command]
fn compact_container(state: State<'_, VaultState>) -> Result<(), String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    store.active()?.compact().map_err(|error| error.to_string())
}

#[tauri::command]
fn list_folders(state: State<'_, VaultState>) -> Result<Vec<String>, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    container.list_folders().map_err(|error| error.to_string())
}

#[tauri::command]
fn create_folder(state: State<'_, VaultState>, path: String) -> Result<Vec<String>, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    container.create_folder(&path).map_err(|error| error.to_string())
}

#[tauri::command]
fn rename_folder(state: State<'_, VaultState>, old_path: String, new_path: String) -> Result<Vec<String>, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    container.rename_folder(&old_path, &new_path).map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_folder(state: State<'_, VaultState>, path: String) -> Result<Vec<String>, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    container.delete_folder(&path).map_err(|error| error.to_string())
}

#[tauri::command]
fn change_password(state: State<'_, VaultState>, password: String, keyfile_path: Option<String>) -> Result<(), String> {
    let mut store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active_mut()?;
    let keyfile = read_keyfile(keyfile_path)?;
    match keyfile.as_deref() {
        Some(keyfile) => container.change_password_with_keyfile(password.as_bytes(), keyfile),
        None => container.change_password(password.as_bytes()),
    }.map_err(|error| error.to_string())
}

#[tauri::command]
fn rotate_recovery_key(state: State<'_, VaultState>) -> Result<String, String> {
    let mut store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active_mut()?;
    container.rotate_recovery_key().map_err(|error| error.to_string())
}

#[tauri::command]
fn rotate_cmk(state: State<'_, VaultState>, password: String, recovery_key: String, keyfile_path: Option<String>) -> Result<(), String> {
    let mut store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active_mut()?;
    let keyfile = read_keyfile(keyfile_path)?;
    match keyfile.as_deref() {
        Some(keyfile) => container.rotate_cmk_with_keyfile(password.as_bytes(), &recovery_key, keyfile),
        None => container.rotate_cmk(password.as_bytes(), &recovery_key),
    }.map_err(|error| error.to_string())
}

#[tauri::command]
fn export_header_backup(state: State<'_, VaultState>, destination_path: String) -> Result<(), String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let backup = store.active()?.export_header_backup().map_err(|error| error.to_string())?;
    fs::write(destination_path, backup).map_err(|error| error.to_string())
}

#[tauri::command]
fn restore_header_backup(path: String, backup_path: String) -> Result<(), String> {
    let mut backup = Vec::new();
    File::open(backup_path).map_err(|error| error.to_string())?.take(128 * 1024).read_to_end(&mut backup).map_err(|error| error.to_string())?;
    Container::restore_header_backup(path, &backup).map_err(|error| error.to_string())
}

#[tauri::command]
fn import_file(state: State<'_, VaultState>, source_path: String, name: String) -> Result<ObjectSummary, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let file = File::open(&source_path).map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    let object = container.import_reader(&name, length, file).map_err(|error| error.to_string())?;
    Ok(summarize(object))
}

#[tauri::command]
fn export_file(state: State<'_, VaultState>, object_id: String, destination_path: String) -> Result<(), String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let object_id = parse_object_id(&object_id)?;
    let bytes = Zeroizing::new(container.export_bytes(object_id).map_err(|error| error.to_string())?);
    fs::write(destination_path, bytes.as_slice()).map_err(|error| error.to_string())
}

#[tauri::command]
fn preview_image(state: State<'_, VaultState>, object_id: String) -> Result<ImagePreview, String> {
    const MAX_PREVIEW_BYTES: usize = 64 * 1024 * 1024;
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let bytes = Zeroizing::new(container.export_bytes(parse_object_id(&object_id)?).map_err(|error| error.to_string())?);
    if bytes.len() > MAX_PREVIEW_BYTES { return Err("imagem excede o limite de preview".to_owned()); }
    let format = image::guess_format(bytes.as_slice()).map_err(|_| "formato de imagem inválido".to_owned())?;
    if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP) {
        return Err("somente PNG, JPEG e WebP podem ser visualizados".to_owned());
    }
    let image = image::load_from_memory(bytes.as_slice()).map_err(|_| "imagem inválida ou não suportada".to_owned())?;
    let rgba = image.to_rgba8();
    if rgba.width() > 8192 || rgba.height() > 8192 || rgba.as_raw().len() > MAX_PREVIEW_BYTES { return Err("dimensões da imagem excedem o limite de preview".to_owned()); }
    Ok(ImagePreview { width: rgba.width(), height: rgba.height(), pixels: rgba.into_raw() })
}

#[tauri::command]
fn decode_contact_card(card_hex: String) -> Result<ContactSummary, String> {
    let card = ContactCard::decode(&parse_hex_vec(&card_hex)?).map_err(|error| error.to_string())?;
    let fingerprint = card.fingerprint_hex();
    Ok(ContactSummary { name: card.name, signing_public: card.public.signing_public.to_vec(), hpke_public: card.public.hpke_public.to_vec(), fingerprint })
}

#[tauri::command]
fn create_contact_card(state: State<'_, VaultState>, name: String) -> Result<String, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let card = ContactCard::new(name, container.identity().public()).map_err(|error| error.to_string())?;
    Ok(hex(&card.encode()))
}

#[tauri::command]
fn open_invitation(state: State<'_, VaultState>, invitation_hex: String) -> Result<InvitationSummary, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let invitation = Invitation::decode(&parse_hex_vec(&invitation_hex)?).map_err(|error| error.to_string())?;
    let payload = invitation.open(container.identity()).map_err(|error| error.to_string())?;
    let owner_hash = blake3::hash(&payload.owner_pubkey);
    Ok(InvitationSummary { object_id: hex(&payload.object_id), swarm_id: hex(&payload.swarm_id), owner_fingerprint: owner_hash.as_bytes()[..8].iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":"), permissions: payload.permissions, expires: payload.capability.expires, relay_hints: payload.relay_hints.clone() })
}

#[tauri::command]
fn download_invitation(state: State<'_, VaultState>, invitation_hex: String, relay_endpoint: String, rendezvous_endpoint: Option<String>) -> Result<ObjectSummary, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let invitation = Invitation::decode(&parse_hex_vec(&invitation_hex)?).map_err(|error| error.to_string())?;
    let payload = invitation.open(container.identity()).map_err(|error| error.to_string())?;
    let mut sources = vec![relay_endpoint.clone()];
    let is_invitation_relay = payload.relay_hints.iter().any(|hint| hint == &relay_endpoint);
    if let Some(rendezvous) = rendezvous_endpoint {
        let discovery_id = derive_discovery_id(&payload.swarm_id);
        let known = RendezvousClient::new(RendezvousClientConfig::default()).query(rendezvous, discovery_id).map_err(|error| error.to_string())?;
        if !is_invitation_relay && !known.iter().any(|record| record.discovery_id == discovery_id && record.relay_endpoint == relay_endpoint) { return Err("relay não foi encontrado no rendezvous do convite".to_owned()); }
        for record in known {
            if record.discovery_id == discovery_id && !sources.iter().any(|source| source == &record.relay_endpoint) { sources.push(record.relay_endpoint); }
        }
    } else if !is_invitation_relay {
        return Err("relay descoberto exige endpoint de rendezvous".to_owned());
    }
    let session = DownloadSession::resume_from_invitation(container, &payload).map_err(|error| error.to_string())?;
    let object = session.download_from_sources(&sources, &RelayConfig::default(), container).map_err(|error| error.to_string())?;
    Ok(summarize(object))
}

#[tauri::command]
fn publish_discovery(state: State<'_, VaultState>, invitation_hex: String, rendezvous_endpoint: String, relay_endpoint: String) -> Result<(), String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let invitation = Invitation::decode(&parse_hex_vec(&invitation_hex)?).map_err(|error| error.to_string())?;
    let payload = invitation.open(container.identity()).map_err(|error| error.to_string())?;
    if !payload.relay_hints.iter().any(|hint| hint == &relay_endpoint) { return Err("endpoint não pertence aos relays do convite".to_owned()); }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "relógio do sistema inválido".to_owned())?.as_secs();
    let expires_at = now.checked_add(MAX_TTL_SECONDS).ok_or_else(|| "validade inválida".to_owned())?.min(payload.capability.expires);
    if expires_at <= now { return Err("capability expirada".to_owned()); }
    let participant = ParticipationKey::from_secret_bytes(payload.participation_secret);
    let record = DiscoveryRecord::signed(derive_discovery_id(&payload.swarm_id), relay_endpoint, expires_at, &participant).map_err(|error| error.to_string())?;
    RendezvousClient::new(RendezvousClientConfig::default()).register(rendezvous_endpoint, &record).map_err(|error| error.to_string())
}

#[tauri::command]
fn query_discovery(state: State<'_, VaultState>, invitation_hex: String, rendezvous_endpoint: String) -> Result<Vec<DiscoverySourceSummary>, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let invitation = Invitation::decode(&parse_hex_vec(&invitation_hex)?).map_err(|error| error.to_string())?;
    let payload = invitation.open(container.identity()).map_err(|error| error.to_string())?;
    let discovery_id = derive_discovery_id(&payload.swarm_id);
    let records = RendezvousClient::new(RendezvousClientConfig::default()).query(rendezvous_endpoint, discovery_id).map_err(|error| error.to_string())?;
    Ok(records.into_iter().filter(|record| record.discovery_id == discovery_id).map(|record| DiscoverySourceSummary { relay_endpoint: record.relay_endpoint, expires_at: record.expires_at }).collect())
}

#[tauri::command]
fn seed_object(state: State<'_, VaultState>, object_id: String, swarm_id: String, relay_endpoint: String) -> Result<(), String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let object_id = parse_object_id(&object_id)?;
    let swarm_id = parse_hex::<32>(&swarm_id)?;
    let material = container.share_material(object_id).map_err(|error| error.to_string())?;
    let manifest_signature = container.sign_manifest(material.manifest_id, swarm_id, object_id);
    let seeder = Seeder::from_container(container, object_id, manifest_signature).map_err(|error| error.to_string())?;
    let owner_pubkey = container.identity().public().signing_public;
    let peer_id = *blake3::hash(&owner_pubkey).as_bytes();
    let revoked_epoch = container.revoked_epoch(swarm_id).map_err(|error| error.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "relógio do sistema inválido".to_owned())?.as_secs();
    drop(store);
    start_seeder(state.inner(), seeder, relay_endpoint, swarm_id, peer_id, owner_pubkey, revoked_epoch, now)
}

fn start_seeder(state: &VaultState, seeder: Seeder, relay_endpoint: String, swarm_id: [u8; 32], peer_id: [u8; 32], owner_pubkey: [u8; 32], revoked_epoch: u64, now: u64) -> Result<(), String> {
    let cancel = Arc::new(AtomicBool::new(true));
    let revoked_epoch = Arc::new(AtomicU64::new(revoked_epoch));
    {
        let mut seed_flags = state.1.lock().map_err(|_| "vault state is unavailable".to_owned())?;
        seed_flags.retain(|seed| seed.cancel.load(Ordering::Acquire));
        if seed_flags.len() >= 16 { return Err("limite de seeders ativos atingido".to_owned()); }
        seed_flags.push(SeedHandle { cancel: Arc::clone(&cancel), swarm_id, revoked_epoch: Arc::clone(&revoked_epoch) });
    }
    let mut config = RelayConfig::default();
    config.idle_timeout = Duration::from_secs(5);
    std::thread::spawn(move || {
        let _ = seeder.serve_until_with_revocation(relay_endpoint, swarm_id, peer_id, &config, owner_pubkey, swarm_id, &revoked_epoch, now, &cancel);
        cancel.store(false, Ordering::Release);
    });
    Ok(())
}

#[tauri::command]
fn seed_invitation(state: State<'_, VaultState>, invitation_hex: String, relay_endpoint: String) -> Result<(), String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let invitation = Invitation::decode(&parse_hex_vec(&invitation_hex)?).map_err(|error| error.to_string())?;
    let payload = invitation.open(container.identity()).map_err(|error| error.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "relógio do sistema inválido".to_owned())?.as_secs();
    if payload.permissions & permission::SEED == 0 || payload.capability.expires <= now || payload.capability.not_before > now { return Err("o convite não autoriza seeding neste momento".to_owned()); }
    let object_id = ObjectId::from_bytes(payload.object_id);
    let seeder = Seeder::from_container(container, object_id, payload.manifest_signature).map_err(|error| error.to_string())?;
    let owner_pubkey = payload.owner_pubkey;
    let peer_id = if container.identity().public().signing_public == owner_pubkey {
        *blake3::hash(&owner_pubkey).as_bytes()
    } else {
        ParticipationKey::from_secret_bytes(payload.participation_secret).peer_id()
    };
    let swarm_id = payload.swarm_id;
    let revoked_epoch = container.revoked_epoch(swarm_id).map_err(|error| error.to_string())?;
    drop(store);
    start_seeder(state.inner(), seeder, relay_endpoint, swarm_id, peer_id, owner_pubkey, revoked_epoch, now)
}

#[tauri::command]
fn revoke_swarm(state: State<'_, VaultState>, swarm_id: String) -> Result<u64, String> {
    let swarm_id = parse_hex::<32>(&swarm_id)?;
    let epoch = {
        let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
        store.active()?.revoke_swarm(swarm_id).map_err(|error| error.to_string())?
    };
    if let Ok(seed_flags) = state.1.lock() {
        for seed in seed_flags.iter().filter(|seed| seed.swarm_id == swarm_id) { seed.revoked_epoch.store(epoch, Ordering::Release); }
    }
    Ok(epoch)
}

#[tauri::command]
fn create_invitation(
    state: State<'_, VaultState>,
    object_id: String,
    recipient_hpke_public: Vec<u8>,
    permissions: u32,
    expires_in_seconds: u64,
    relay_hints: Vec<String>,
) -> Result<CreatedInvitation, String> {
    let store = state.0.lock().map_err(|_| "vault state is unavailable".to_owned())?;
    let container = store.active()?;
    let object_id = parse_object_id(&object_id)?;
    let recipient: [u8; 32] = recipient_hpke_public.try_into().map_err(|_| "chave HPKE do destinatário inválida".to_owned())?;
    let allowed = permission::DOWNLOAD | permission::SEED | permission::DELEGATE | permission::PUBLISH;
    if permissions == 0 || permissions & !allowed != 0 { return Err("permissões inválidas".to_owned()); }
    if relay_hints.is_empty() { return Err("configure ao menos um relay privado antes de emitir o convite".to_owned()); }
    if !(1..=30 * 24 * 60 * 60).contains(&expires_in_seconds) { return Err("validade do convite deve estar entre 1 segundo e 30 dias".to_owned()); }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "relógio do sistema inválido".to_owned())?.as_secs();
    let expires = now.checked_add(expires_in_seconds).ok_or_else(|| "validade inválida".to_owned())?;
    let material = container.share_material(object_id).map_err(|error| error.to_string())?;
    let mut swarm_id = [0u8; 32];
    OsRng.fill_bytes(&mut swarm_id);
    let participant = ParticipationKey::generate();
    let capability = Capability::new(swarm_id, Some(*object_id.as_bytes()), participant.public_key(), permissions, now, expires, 0).sign(container.identity().signing_key());
    let participation_secret = participant.secret_bytes();
    let manifest_signature = container.sign_manifest(material.manifest_id, swarm_id, object_id);
    let payload = InvitationPayload { object_id: *object_id.as_bytes(), manifest_id: material.manifest_id, manifest_signature, swarm_id, owner_pubkey: container.identity().public().signing_public, cek: material.cek, participation_secret: *participation_secret, capability, relay_hints, permissions };
    let invitation = Invitation::seal(&payload, &recipient, container.identity().signing_key()).map_err(|error| error.to_string())?;
    let encoded = invitation.encode().map_err(|error| error.to_string())?;
    Ok(CreatedInvitation { invitation: hex(&encoded), object_id: hex(object_id.as_bytes()), swarm_id: hex(&swarm_id), relay_hints: payload.relay_hints.clone() })
}

fn parse_object_id(value: &str) -> Result<ObjectId, String> {
    Ok(ObjectId::from_bytes(parse_hex::<16>(value)?))
}

fn read_keyfile(path: Option<String>) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let Some(path) = path else { return Ok(None); };
    let mut bytes = Vec::new();
    File::open(path).map_err(|error| error.to_string())?.take((MAX_KEYFILE_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_KEYFILE_BYTES { return Err("keyfile inválido ou maior que 1 MiB".to_owned()); }
    Ok(Some(Zeroizing::new(bytes)))
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = parse_hex_vec(value)?;
    bytes.try_into().map_err(|_| "identificador hexadecimal inválido".to_owned())
}

fn parse_hex_vec(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 2 != 0 || value.len() > 2048 { return Err("identificador hexadecimal inválido".to_owned()); }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16).ok_or_else(|| "identificador hexadecimal inválido".to_owned())? as u8;
        let low = (pair[1] as char).to_digit(16).ok_or_else(|| "identificador hexadecimal inválido".to_owned())? as u8;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultState(Mutex::new(ContainerStore::default()), Mutex::new(Vec::new())))
        .invoke_handler(tauri::generate_handler![create_container, unlock_container, unlock_container_recovery, activate_container, lock_container, list_objects, list_folders, create_folder, rename_folder, delete_folder, rename_object, copy_object, delete_object, compact_container, change_password, rotate_recovery_key, rotate_cmk, export_header_backup, restore_header_backup, import_file, export_file, preview_image, decode_contact_card, create_contact_card, open_invitation, download_invitation, publish_discovery, query_discovery, seed_object, seed_invitation, revoke_swarm, create_invitation])
        .run(tauri::generate_context!())
        .expect("error while running Vault Network");
}
