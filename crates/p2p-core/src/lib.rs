//! Application core. The GUI talks only to [`Core`]; all keys, crypto and networking live here.
//!
//! Lifecycle: `NoVault` → [`Core::create_vault`] / [`Core::unlock`] → `Unlocked` (Tor starts in
//! the background) → [`Core::lock`] (Tor stops, keys wiped from memory) → `Locked`.

pub mod db;
mod net;
pub mod pairing;
mod peer;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use p2p_proto::{Content, FILE_CHUNK_BYTES, ProstMessage, content};
use p2p_signal::Identity;
use p2p_transport::noise::NoiseKeypair;
use p2p_transport::onion::{ClientAuthKey, ServiceId};
use p2p_transport::tor::OnionKey;
use p2p_vault::{KdfParams, Vault};
use serde::Serialize;
use tokio::sync::broadcast;
use zeroize::Zeroizing;

pub use db::{FileView, MessageView, Settings};
pub use p2p_proto::MAX_FILE_BYTES;

/// Longest text message accepted (UTF-8 bytes).
pub const MAX_TEXT_BYTES: usize = 16_000;
/// How many safety-number groups must be typed in (as read aloud by the friend) to verify.
pub const VERIFY_GROUPS_REQUIRED: usize = 2;
/// Disappearing-message timers offered (seconds); 0 = off.
pub const MAX_DISAPPEAR_SECS: u32 = 4 * 7 * 24 * 3600;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("{0}")]
    Vault(#[from] p2p_vault::VaultError),
    #[error("{0}")]
    Pairing(#[from] pairing::PairingError),
    #[error("encryption error: {0}")]
    Signal(#[from] p2p_signal::Error),
    #[error("database error: {0}")]
    Db(#[from] p2p_vault::rusqlite::Error),
    #[error("the app is locked")]
    Locked,
    #[error("contact not found")]
    NoContact,
    #[error("verify this contact's safety number before sending messages")]
    NotVerified,
    #[error("those digits don't match. Do NOT verify: compare again, and if they still differ, delete this contact and pair again")]
    SafetyMismatch,
    #[error("that is your own pairing code")]
    OwnCode,
    #[error("this contact is already paired")]
    AlreadyPaired,
    #[error("message is empty or too long")]
    BadMessage,
    #[error("files must be between 1 byte and {} MB", MAX_FILE_BYTES / (1024 * 1024))]
    BadFile,
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;

/// Events pushed to the GUI.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Tor bootstrap progress / readiness.
    Tor { progress: u8, ready: bool, error: Option<String> },
    /// A contact became reachable or unreachable.
    Presence { contact_id: i64, online: bool },
    /// A new or updated message.
    Message { message: MessageView },
    /// Messages removed (disappearing timer).
    Deleted { contact_id: i64, ids: Vec<String> },
    /// Contact list or a contact's settings changed.
    Contacts,
    /// Something that needs the user's attention (e.g. a key mismatch).
    Security { contact_id: i64, message: String },
    /// The vault was locked.
    Locked,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppState {
    NoVault,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContactView {
    pub id: i64,
    pub name: String,
    pub onion: String,
    pub verified: bool,
    pub online: bool,
    pub disappear_secs: u32,
    pub unread: i64,
    pub queued: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MyCode {
    pub code: String,
    pub qr_svg: String,
    pub onion: String,
    pub name: String,
}

pub struct Config {
    /// Where the vault and Tor state live.
    pub data_dir: PathBuf,
    /// Explicit Tor binary (otherwise: next to the executable, then PATH).
    pub tor_binary: Option<PathBuf>,
    /// Pluggable-transport binary for bridges.
    pub pt_binary: Option<PathBuf>,
    pub kdf: KdfParams,
}

/// Everything that exists only while unlocked. Dropping it wipes key material.
pub(crate) struct Unlocked {
    pub vault: Vault,
    pub identity: Identity,
    pub noise: Arc<NoiseKeypair>,
    pub client_auth: ClientAuthKey,
    pub onion_key: OnionKey,
    pub onion_id: ServiceId,
    pub name: String,
}

pub(crate) struct Inner {
    pub cfg: Config,
    pub events: broadcast::Sender<Event>,
    pub state: Mutex<Option<Unlocked>>,
    pub net: tokio::sync::Mutex<net::NetSlot>,
}

impl Inner {
    /// Runs `f` with the unlocked state. Never call across an `.await`.
    pub fn with<T>(&self, f: impl FnOnce(&mut Unlocked) -> Result<T>) -> Result<T> {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let u = g.as_mut().ok_or(CoreError::Locked)?;
        f(u)
    }

    pub fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }
}

#[derive(Clone)]
pub struct Core {
    inner: Arc<Inner>,
}

const META_IDENTITY: &str = "identity";
const META_NOISE: &str = "noise_secret";
const META_CLIENT_AUTH: &str = "client_auth_secret";
const META_ONION_KEY: &str = "onion_key";
const META_ONION_ID: &str = "onion_id";
const META_NAME: &str = "display_name";

fn vault_dir(cfg: &Config) -> PathBuf {
    cfg.data_dir.join("vault")
}

impl Core {
    pub fn new(cfg: Config) -> Core {
        let (events, _) = broadcast::channel(512);
        Core {
            inner: Arc::new(Inner {
                cfg,
                events,
                state: Mutex::new(None),
                net: tokio::sync::Mutex::new(net::NetSlot::Off),
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    pub fn state(&self) -> AppState {
        if self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            AppState::Unlocked
        } else if p2p_vault::exists(&vault_dir(&self.inner.cfg)) {
            AppState::Locked
        } else {
            AppState::NoVault
        }
    }

    /// First run: creates the vault and all long-term keys, then starts networking.
    pub async fn create_vault(&self, display_name: &str, passphrase: Zeroizing<String>) -> Result<()> {
        let name = pairing::sanitize_name(display_name);
        if name.is_empty() {
            return Err(CoreError::Invalid("name"));
        }
        let dir = vault_dir(&self.inner.cfg);
        let kdf = self.inner.cfg.kdf;
        let unlocked = tokio::task::spawn_blocking(move || -> Result<Unlocked> {
            let vault = Vault::create(&dir, &passphrase, kdf, db::MIGRATIONS)?;
            let identity = Identity::generate();
            let noise = NoiseKeypair::generate();
            let client_auth = ClientAuthKey::generate();
            let (onion_blob, onion_id) = p2p_transport::onion::generate_onion_identity();
            let c = vault.conn();
            let tx = c.unchecked_transaction()?;
            db::meta_set(c, META_IDENTITY, &identity.to_bytes())?;
            db::meta_set(c, META_NOISE, noise.secret_bytes())?;
            db::meta_set(c, META_CLIENT_AUTH, client_auth.secret_bytes().as_ref())?;
            db::meta_set(c, META_ONION_KEY, onion_blob.as_bytes())?;
            db::meta_set(c, META_ONION_ID, onion_id.as_str().as_bytes())?;
            db::meta_set(c, META_NAME, name.as_bytes())?;
            db::settings_set(c, &Settings::default())?;
            tx.commit()?;
            p2p_signal::maintenance(c, &identity)?;
            Ok(Unlocked {
                vault,
                identity,
                noise: Arc::new(noise),
                client_auth,
                onion_key: OnionKey::from_blob(onion_blob.to_string()),
                onion_id,
                name,
            })
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))??;
        self.activate(unlocked).await
    }

    pub async fn unlock(&self, passphrase: Zeroizing<String>) -> Result<()> {
        if self.state() == AppState::Unlocked {
            return Ok(());
        }
        let dir = vault_dir(&self.inner.cfg);
        let unlocked = tokio::task::spawn_blocking(move || -> Result<Unlocked> {
            let vault = Vault::open(&dir, &passphrase, db::MIGRATIONS)?;
            let c = vault.conn();
            let need = |k: &str| -> Result<Zeroizing<Vec<u8>>> {
                db::meta_get(c, k)?.map(Zeroizing::new).ok_or(CoreError::Internal(format!("missing {k}")))
            };
            let identity = Identity::from_bytes(&need(META_IDENTITY)?)?;
            let noise_secret: [u8; 32] =
                need(META_NOISE)?.as_slice().try_into().map_err(|_| CoreError::Internal("noise key".into()))?;
            let auth_secret: [u8; 32] =
                need(META_CLIENT_AUTH)?.as_slice().try_into().map_err(|_| CoreError::Internal("auth key".into()))?;
            let onion_key = String::from_utf8(need(META_ONION_KEY)?.to_vec())
                .map_err(|_| CoreError::Internal("onion key".into()))?;
            let onion_id = ServiceId::parse(&String::from_utf8_lossy(&need(META_ONION_ID)?))
                .map_err(|_| CoreError::Internal("onion id".into()))?;
            let name = String::from_utf8_lossy(&need(META_NAME)?).into_owned();
            p2p_signal::maintenance(c, &identity)?;
            Ok(Unlocked {
                vault,
                identity,
                noise: Arc::new(NoiseKeypair::from_secret(Zeroizing::new(noise_secret))),
                client_auth: ClientAuthKey::from_bytes(auth_secret),
                onion_key: OnionKey::from_blob(onion_key),
                onion_id,
                name,
            })
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))??;
        self.activate(unlocked).await
    }

    async fn activate(&self, unlocked: Unlocked) -> Result<()> {
        *self.inner.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(unlocked);
        net::start(self.inner.clone()).await;
        Ok(())
    }

    /// Checks the passphrase without changing state (screen-lock unlock).
    pub async fn verify_passphrase(&self, passphrase: Zeroizing<String>) -> Result<bool> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.with(|u| Ok(u.vault.verify_passphrase(&passphrase))))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?
    }

    /// Stops networking and wipes all keys from memory. Messages can't be received while locked.
    pub async fn lock(&self) {
        net::stop(&self.inner).await;
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(state);
        self.inner.emit(Event::Locked);
    }

    pub async fn change_passphrase(&self, old: Zeroizing<String>, new: Zeroizing<String>) -> Result<()> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.with(|u| Ok(u.vault.change_passphrase(&old, &new)?)))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?
    }

    /// Destroys everything: vault, keys, Tor state. Irreversible.
    pub async fn panic_wipe(&self) -> Result<()> {
        net::stop(&self.inner).await;
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).take();
        match state {
            Some(u) => u.vault.destroy()?,
            None => p2p_vault::destroy_dir_contents(&vault_dir(&self.inner.cfg))?,
        }
        let _ = std::fs::remove_dir_all(self.inner.cfg.data_dir.join("tor"));
        self.inner.emit(Event::Locked);
        Ok(())
    }

    // -------------------------------------------------------------- pairing

    pub fn my_code(&self) -> Result<MyCode> {
        self.inner.with(|u| {
            let code = pairing::encode(&u.identity, &u.name, &u.onion_id, &u.noise.public(), &u.client_auth.public_bytes())?;
            Ok(MyCode { qr_svg: pairing::qr_svg(&code), code, onion: u.onion_id.hostname(), name: u.name.clone() })
        })
    }

    /// Adds a contact from their pairing code. The contact starts **unverified**.
    pub async fn add_contact(&self, code: &str, nickname: Option<&str>) -> Result<i64> {
        let parsed = pairing::decode(code)?;
        let id = self.inner.with(|u| {
            if parsed.identity_key == u.identity.public_bytes() || parsed.onion == u.onion_id {
                return Err(CoreError::OwnCode);
            }
            let c = u.vault.conn();
            let name = nickname.map(pairing::sanitize_name).filter(|n| !n.is_empty()).unwrap_or(parsed.display_name.clone());
            let name = if name.is_empty() { "Friend".to_string() } else { name };
            let tx = c.unchecked_transaction()?;
            let id = match db::insert_contact(
                c,
                &name,
                parsed.onion.as_str(),
                &parsed.identity_key,
                &parsed.noise_static,
                &parsed.client_auth_pub,
            ) {
                Ok(id) => id,
                Err(p2p_vault::rusqlite::Error::SqliteFailure(e, _))
                    if e.code == p2p_vault::rusqlite::ErrorCode::ConstraintViolation =>
                {
                    return Err(CoreError::AlreadyPaired);
                }
                Err(e) => return Err(e.into()),
            };
            p2p_signal::trust(c, &parsed.identity_key)?;
            tx.commit()?;
            Ok(id)
        })?;
        self.inner.emit(Event::Contacts);
        net::contacts_changed(&self.inner).await;
        Ok(id)
    }

    pub fn safety_number(&self, contact_id: i64) -> Result<Vec<String>> {
        self.inner.with(|u| {
            let c = db::contact(u.vault.conn(), contact_id)?.ok_or(CoreError::NoContact)?;
            let digits = p2p_signal::safety_number(&u.identity.public_bytes(), &c.identity_key)?;
            Ok(pairing::format_safety_number(&digits))
        })
    }

    /// Marks a contact verified. Requires proof that the safety number was really compared:
    /// `proof` holds at least [`VERIFY_GROUPS_REQUIRED`] distinct (group index, digits) pairs
    /// that the user typed in as the friend read them aloud from *their* screen. Under a
    /// man-in-the-middle the friend's digits differ from ours, so verification fails.
    pub fn verify_contact(&self, contact_id: i64, proof: &[(usize, String)]) -> Result<()> {
        let groups = self.safety_number(contact_id)?;
        let mut seen = std::collections::HashSet::new();
        for (i, typed) in proof {
            if !seen.insert(*i) {
                return Err(CoreError::Invalid("the same group was entered twice"));
            }
            let expected = groups.get(*i).ok_or(CoreError::Invalid("group number"))?;
            let typed: String = typed.chars().filter(|c| !c.is_whitespace()).collect();
            if typed != *expected {
                return Err(CoreError::SafetyMismatch);
            }
        }
        if seen.len() < VERIFY_GROUPS_REQUIRED {
            return Err(CoreError::Invalid("enter the requested groups of digits"));
        }
        self.set_verified_flag(contact_id, true)
    }

    /// Removes verification (sending is disabled again).
    pub fn unverify_contact(&self, contact_id: i64) -> Result<()> {
        self.set_verified_flag(contact_id, false)
    }

    fn set_verified_flag(&self, contact_id: i64, verified: bool) -> Result<()> {
        self.inner.with(|u| {
            let n = u.vault.conn().execute(
                "UPDATE contacts SET verified = ?1 WHERE id = ?2",
                p2p_vault::rusqlite::params![verified as i64, contact_id],
            )?;
            if n == 0 {
                return Err(CoreError::NoContact);
            }
            Ok(())
        })?;
        self.inner.emit(Event::Contacts);
        Ok(())
    }

    /// Test helper: verify by reading our own safety number (what a perfect call would give).
    #[doc(hidden)]
    pub fn verify_contact_for_tests(&self, contact_id: i64) -> Result<()> {
        let g = self.safety_number(contact_id)?;
        self.verify_contact(contact_id, &[(2, g[2].clone()), (9, g[9].clone())])
    }

    pub fn rename_contact(&self, contact_id: i64, name: &str) -> Result<()> {
        let name = pairing::sanitize_name(name);
        if name.is_empty() {
            return Err(CoreError::Invalid("name"));
        }
        self.inner.with(|u| {
            u.vault.conn().execute(
                "UPDATE contacts SET name = ?1 WHERE id = ?2",
                p2p_vault::rusqlite::params![name, contact_id],
            )?;
            Ok(())
        })?;
        self.inner.emit(Event::Contacts);
        Ok(())
    }

    /// Deletes a contact, all messages with them, and the Signal session.
    pub async fn delete_contact(&self, contact_id: i64) -> Result<()> {
        let contact = self.inner.with(|u| {
            let c = u.vault.conn();
            let contact = db::contact(c, contact_id)?.ok_or(CoreError::NoContact)?;
            let tx = c.unchecked_transaction()?;
            p2p_signal::forget(c, &contact.identity_key)?;
            c.execute("DELETE FROM contacts WHERE id = ?1", [contact_id])?;
            tx.commit()?;
            Ok(contact)
        })?;
        net::contact_removed(&self.inner, &contact).await;
        self.inner.emit(Event::Contacts);
        Ok(())
    }

    pub async fn contacts(&self) -> Result<Vec<ContactView>> {
        let online = net::online_contacts(&self.inner).await;
        self.inner.with(|u| {
            let c = u.vault.conn();
            db::contacts(c)?
                .into_iter()
                .map(|k| {
                    Ok(ContactView {
                        online: online.contains(&k.id),
                        unread: db::unread_count(c, k.id)?,
                        queued: db::outbox_count(c, k.id)?,
                        id: k.id,
                        name: k.name,
                        onion: k.onion,
                        verified: k.verified,
                        disappear_secs: k.disappear_secs,
                    })
                })
                .collect()
        })
    }

    // -------------------------------------------------------------- messaging

    pub fn messages(&self, contact_id: i64, limit: u32, before_ts: Option<i64>) -> Result<Vec<MessageView>> {
        self.inner.with(|u| Ok(db::messages(u.vault.conn(), contact_id, limit.clamp(1, 500), before_ts)?))
    }

    /// Queues a text message; it is encrypted and sent as soon as the contact is reachable.
    pub async fn send_text(&self, contact_id: i64, text: &str) -> Result<MessageView> {
        let text = text.trim_end();
        if text.trim().is_empty() || text.len() > MAX_TEXT_BYTES {
            return Err(CoreError::BadMessage);
        }
        let view = self.inner.with(|u| {
            let c = u.vault.conn();
            let contact = db::contact(c, contact_id)?.ok_or(CoreError::NoContact)?;
            if !contact.verified {
                return Err(CoreError::NotVerified);
            }
            let id = db::random_id();
            let content = Content {
                id: id.clone(),
                sent_at_ms: db::now_ms() as u64,
                expire_secs: contact.disappear_secs,
                body: Some(content::Body::Text(text.to_string())),
            };
            let tx = c.unchecked_transaction()?;
            db::insert_message(c, &id, contact_id, None, true, db::KIND_TEXT, text, content.sent_at_ms as i64, db::OUT_QUEUED, contact.disappear_secs)?;
            db::outbox_push(c, &id, contact_id, Some(&id), &Zeroizing::new(content.encode_to_vec()))?;
            tx.commit()?;
            db::message(c, &id)?.ok_or(CoreError::Internal("message vanished".into()))
        })?;
        self.inner.emit(Event::Message { message: view.clone() });
        net::kick(&self.inner, contact_id).await;
        Ok(view)
    }

    /// Queues a file. It is sent in encrypted chunks after any queued text messages, and shows
    /// progress as chunks are delivered. The sender keeps no copy of the data once delivered.
    pub async fn send_file(&self, contact_id: i64, name: &str, data: Zeroizing<Vec<u8>>) -> Result<MessageView> {
        if data.is_empty() || data.len() as u64 > MAX_FILE_BYTES {
            return Err(CoreError::BadFile);
        }
        let name = sanitize_file_name(name);
        let inner = self.inner.clone();
        let view = tokio::task::spawn_blocking(move || {
            inner.with(|u| {
                use sha2::Digest;
                let c = u.vault.conn();
                let contact = db::contact(c, contact_id)?.ok_or(CoreError::NoContact)?;
                if !contact.verified {
                    return Err(CoreError::NotVerified);
                }
                let id = db::random_id();
                let now = db::now_ms();
                let chunk_count = data.len().div_ceil(FILE_CHUNK_BYTES) as u32;
                let sha256 = sha2::Sha256::digest(&data[..]).to_vec();
                let header = Content {
                    id: id.clone(),
                    sent_at_ms: now as u64,
                    expire_secs: contact.disappear_secs,
                    body: Some(content::Body::FileHeader(p2p_proto::FileHeader {
                        name: name.clone(),
                        size: data.len() as u64,
                        chunk_count,
                        sha256: sha256.clone(),
                    })),
                };
                let tx = c.unchecked_transaction()?;
                db::insert_message(c, &id, contact_id, None, true, db::KIND_FILE, &name, now, db::OUT_QUEUED, contact.disappear_secs)?;
                db::insert_attachment(c, &id, &name, data.len() as i64, &sha256, chunk_count, db::FILE_SENDING)?;
                db::outbox_push_file_part(c, &db::random_id(), contact_id, &id, false, &header.encode_to_vec())?;
                for (index, chunk) in data.chunks(FILE_CHUNK_BYTES).enumerate() {
                    let part = Content {
                        id: db::random_id(),
                        sent_at_ms: now as u64,
                        expire_secs: 0,
                        body: Some(content::Body::FileChunk(p2p_proto::FileChunk {
                            file_id: id.clone(),
                            index: index as u32,
                            data: chunk.to_vec(),
                        })),
                    };
                    db::outbox_push_file_part(c, &part.id, contact_id, &id, true, &Zeroizing::new(part.encode_to_vec()))?;
                }
                tx.commit()?;
                db::message(c, &id)?.ok_or(CoreError::Internal("message vanished".into()))
            })
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))??;
        self.inner.emit(Event::Message { message: view.clone() });
        self.inner.emit(Event::Contacts);
        net::kick(&self.inner, contact_id).await;
        Ok(view)
    }

    /// The contents of a completely received file, with its suggested name (for "Save as").
    pub fn file_data(&self, message_id_hex: &str) -> Result<(String, Zeroizing<Vec<u8>>)> {
        let id = hex::decode(message_id_hex).map_err(|_| CoreError::Invalid("message id"))?;
        self.inner.with(|u| {
            let c = u.vault.conn();
            let view = db::message(c, &id)?.ok_or(CoreError::Invalid("message id"))?;
            let file = view.file.filter(|f| f.state == "received").ok_or(CoreError::Invalid("file not available"))?;
            let mut data = Zeroizing::new(Vec::with_capacity(file.size as usize));
            db::for_each_chunk(c, &id, |chunk| data.extend_from_slice(chunk))?;
            Ok((file.name, data))
        })
    }

    /// Marks a conversation read; sends read receipts if enabled.
    pub async fn mark_read(&self, contact_id: i64) -> Result<()> {
        let queued = self.inner.with(|u| {
            let c = u.vault.conn();
            // Mark locally read regardless; only *send* a receipt to a verified contact. An
            // unverified contact may be an impostor, so don't leak read status to them.
            let verified = db::contact(c, contact_id)?.is_some_and(|k| k.verified);
            let ids = db::mark_read(c, contact_id)?;
            if ids.is_empty() || !verified || !db::settings_get(c)?.read_receipts {
                return Ok(false);
            }
            let id = db::random_id();
            let content = Content {
                id: id.clone(),
                sent_at_ms: db::now_ms() as u64,
                expire_secs: 0,
                body: Some(content::Body::ReadReceipt(p2p_proto::ReadReceipt { ids })),
            };
            db::outbox_push(c, &id, contact_id, None, &content.encode_to_vec())?;
            Ok(true)
        })?;
        self.inner.emit(Event::Contacts);
        if queued {
            net::kick(&self.inner, contact_id).await;
        }
        Ok(())
    }

    /// Sets the disappearing-message timer for a conversation (both sides).
    pub async fn set_disappearing(&self, contact_id: i64, secs: u32) -> Result<()> {
        if secs > MAX_DISAPPEAR_SECS {
            return Err(CoreError::Invalid("timer"));
        }
        let view = self.inner.with(|u| {
            let c = u.vault.conn();
            let contact = db::contact(c, contact_id)?.ok_or(CoreError::NoContact)?;
            if !contact.verified {
                return Err(CoreError::NotVerified);
            }
            let tx = c.unchecked_transaction()?;
            c.execute(
                "UPDATE contacts SET disappear_secs = ?1 WHERE id = ?2",
                p2p_vault::rusqlite::params![secs, contact_id],
            )?;
            let id = db::random_id();
            let content = Content {
                id: id.clone(),
                sent_at_ms: db::now_ms() as u64,
                expire_secs: 0,
                body: Some(content::Body::TimerUpdate(p2p_proto::TimerUpdate { expire_secs: secs })),
            };
            db::insert_message(c, &id, contact_id, None, true, db::KIND_SYSTEM, &timer_text(secs, true), content.sent_at_ms as i64, db::OUT_QUEUED, 0)?;
            db::outbox_push(c, &id, contact_id, Some(&id), &content.encode_to_vec())?;
            tx.commit()?;
            db::message(c, &id)?.ok_or(CoreError::Internal("message vanished".into()))
        })?;
        self.inner.emit(Event::Message { message: view });
        self.inner.emit(Event::Contacts);
        net::kick(&self.inner, contact_id).await;
        Ok(())
    }

    // -------------------------------------------------------------- settings

    pub fn settings(&self) -> Result<Settings> {
        self.inner.with(|u| Ok(db::settings_get(u.vault.conn())?))
    }

    /// Saves settings. Changing bridges restarts Tor.
    pub async fn set_settings(&self, s: Settings) -> Result<()> {
        let mut s = s;
        s.bridges = s.bridges.iter().map(|b| b.trim().to_string()).filter(|b| !b.is_empty()).take(20).collect();
        if s.bridges.iter().any(|b| b.len() > 1000) {
            return Err(CoreError::Invalid("bridge line"));
        }
        let bridges_changed = self.inner.with(|u| {
            let c = u.vault.conn();
            let old = db::settings_get(c)?;
            db::settings_set(c, &s)?;
            Ok(old.bridges != s.bridges)
        })?;
        if bridges_changed {
            net::stop(&self.inner).await;
            net::start(self.inner.clone()).await;
        }
        Ok(())
    }

    /// Recent Tor log lines for troubleshooting.
    pub async fn tor_log(&self) -> Vec<String> {
        net::tor_log(&self.inner).await
    }
}

/// Keeps only a plain file name: no directories, control or reserved characters, bounded length.
pub(crate) fn sanitize_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base
        .chars()
        // Reserved on Windows, and invisible/bidi characters that could disguise an extension
        // ("invoice\u{202e}fdp.exe" displays as "invoiceexe.pdf").
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        })
        .take(120)
        .collect();
    let clean = clean.trim().trim_start_matches('.').trim_end_matches(['.', ' ']).to_string();
    if clean.is_empty() { "file".to_string() } else { clean }
}

pub(crate) fn timer_text(secs: u32, by_me: bool) -> String {
    let who = if by_me { "You" } else { "Your contact" };
    if secs == 0 {
        return format!("{who} turned off disappearing messages.");
    }
    let human = match secs {
        s if s % 86400 == 0 => format!("{} day{}", s / 86400, if s / 86400 == 1 { "" } else { "s" }),
        s if s % 3600 == 0 => format!("{} hour{}", s / 3600, if s / 3600 == 1 { "" } else { "s" }),
        s if s % 60 == 0 => format!("{} minute{}", s / 60, if s / 60 == 1 { "" } else { "s" }),
        s => format!("{s} seconds"),
    };
    format!("{who} set disappearing messages to {human}.")
}

#[cfg(test)]
mod tests;
