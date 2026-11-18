//! Signal protocol on top of the encrypted vault.
//!
//! Uses Signal's official `libsignal-protocol`: PQXDH session setup (X25519 + ML-KEM-1024),
//! the Double Ratchet, and — in this libsignal version — the SPQR post-quantum ratchet.
//! All protocol state (sessions, prekeys, trusted identities) lives in vault tables.
//!
//! libsignal's store traits are async but our stores are synchronous SQLite calls, so every
//! future completes immediately; we drive them with a local `block_on` and expose a plain
//! synchronous API.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, Direction, Fingerprint, GenericSignedPreKey,
    IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage,
    PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore, SessionUsabilityRequirements,
    SignalMessage, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
    Timestamp, kem,
};
use p2p_proto::{Bundle, ENVELOPE_PREKEY, ENVELOPE_WHISPER};
use p2p_vault::rusqlite::{self, Connection, OptionalExtension, params};
use rand::{Rng, TryRngCore, rngs::OsRng};
use zeroize::Zeroizing;

/// Vault tables used by this crate. The app includes this in its migrations.
pub const SCHEMA: &str = "
CREATE TABLE signal_trusted (address TEXT PRIMARY KEY, identity BLOB NOT NULL);
CREATE TABLE signal_sessions (address TEXT PRIMARY KEY, record BLOB NOT NULL);
CREATE TABLE signal_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE signal_signed_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE signal_kyber_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL, created_at INTEGER NOT NULL);
";

/// Signed prekeys are rotated after this age.
pub const SIGNED_PREKEY_ROTATE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
/// Old signed prekeys are kept this long for in-flight session setups, then erased.
pub const SIGNED_PREKEY_KEEP: Duration = Duration::from_secs(30 * 24 * 3600);
/// Unused one-time prekeys (handed out but never used) are erased after this age.
pub const ONE_TIME_PREKEY_KEEP: Duration = Duration::from_secs(14 * 24 * 3600);

/// Upper bound on stored, not-yet-used one-time prekeys of each kind.
pub const MAX_UNUSED_ONE_TIME_KEYS: i64 = 20;

/// Session requirements: not stale, and established with post-quantum PQXDH.
fn usable() -> SessionUsabilityRequirements {
    SessionUsabilityRequirements::NotStale | SessionUsabilityRequirements::EstablishedWithPqxdh
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("signal protocol: {0}")]
    Signal(#[from] SignalProtocolError),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("the peer's identity key does not match the verified one")]
    UntrustedIdentity,
    #[error("invalid bundle: {0}")]
    BadBundle(&'static str),
    #[error("unknown envelope type")]
    BadEnvelope,
    #[error("invalid padding")]
    BadPadding,
    #[error("invalid identity record")]
    BadIdentity,
}

pub type Result<T> = std::result::Result<T, Error>;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures_executor::block_on(f)
}

fn rng() -> impl rand::CryptoRng + Rng {
    OsRng.unwrap_err()
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn device() -> DeviceId {
    DeviceId::new(1).expect("1 is a valid device id")
}

/// Signal address of a peer. We name peers by the hex of their (pinned) identity key, which
/// is globally unique and stable for the lifetime of the pairing.
pub fn peer_address(identity_key: &[u8]) -> ProtocolAddress {
    ProtocolAddress::new(hex::encode(identity_key), device())
}

fn local_address() -> ProtocolAddress {
    ProtocolAddress::new("local".to_string(), device())
}

// ------------------------------------------------------------------- identity

/// Our long-term Signal identity.
pub struct Identity {
    pair: IdentityKeyPair,
    registration_id: u32,
}

impl Identity {
    pub fn generate() -> Identity {
        let mut r = rng();
        let pair = IdentityKeyPair::generate(&mut r);
        // Signal registration IDs are 14-bit.
        let registration_id = r.random_range(1..16380);
        Identity { pair, registration_id }
    }

    /// Serialization for the vault (contains the private key).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(self.registration_id.to_be_bytes().to_vec());
        out.extend_from_slice(&self.pair.serialize());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Identity> {
        if bytes.len() < 5 {
            return Err(Error::BadIdentity);
        }
        let registration_id = u32::from_be_bytes(bytes[..4].try_into().expect("4 bytes"));
        let pair = IdentityKeyPair::try_from(&bytes[4..])?;
        Ok(Identity { pair, registration_id })
    }

    /// Public identity key bytes (33 bytes), as shared in pairing codes.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.pair.identity_key().serialize().to_vec()
    }

    /// XEdDSA signature with the identity key (used for pairing codes).
    pub fn sign(&self, context: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let mut data = Zeroizing::new(context.to_vec());
        data.extend_from_slice(message);
        Ok(self.pair.private_key().calculate_signature(&data, &mut rng()).map_err(SignalProtocolError::from)?.into_vec())
    }
}

/// Verifies an identity-key signature made by [`Identity::sign`].
pub fn verify_signature(identity_key: &[u8], context: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = IdentityKey::decode(identity_key) else { return false };
    let mut data = context.to_vec();
    data.extend_from_slice(message);
    key.public_key().verify_signature(&data, signature)
}

/// Checks that bytes are a well-formed identity public key.
pub fn is_valid_identity_key(identity_key: &[u8]) -> bool {
    IdentityKey::decode(identity_key).is_ok()
}

/// The 60-digit safety number for (our key, their key). Both sides compute the same digits.
pub fn safety_number(local_identity: &[u8], remote_identity: &[u8]) -> Result<String> {
    let local = IdentityKey::decode(local_identity)?;
    let remote = IdentityKey::decode(remote_identity)?;
    // Version 2 / 5200 iterations, as in Signal. Stable identifiers are the keys themselves.
    let fp = Fingerprint::new(2, 5200, local_identity, &local, remote_identity, &remote)
        .map_err(|e| Error::Signal(SignalProtocolError::InvalidArgument(e.to_string())))?;
    fp.display_string().map_err(|e| Error::Signal(SignalProtocolError::InvalidArgument(e.to_string())))
}

// ------------------------------------------------------------------- trust

/// Pins `identity_key` as the only trusted identity for that peer (done at pairing).
pub fn trust(conn: &Connection, identity_key: &[u8]) -> Result<()> {
    let addr = peer_address(identity_key);
    conn.execute(
        "INSERT INTO signal_trusted (address, identity) VALUES (?1, ?2)
         ON CONFLICT(address) DO UPDATE SET identity = excluded.identity",
        params![addr.name(), identity_key],
    )?;
    Ok(())
}

/// Forgets a peer completely: trust and session.
pub fn forget(conn: &Connection, identity_key: &[u8]) -> Result<()> {
    let addr = peer_address(identity_key);
    conn.execute("DELETE FROM signal_trusted WHERE address = ?1", [addr.name()])?;
    conn.execute("DELETE FROM signal_sessions WHERE address = ?1", [addr.name()])?;
    Ok(())
}

// ------------------------------------------------------------------- stores

struct Store<'a> {
    conn: &'a Connection,
    identity: &'a Identity,
}

#[async_trait(?Send)]
impl IdentityKeyStore for Store<'_> {
    async fn get_identity_key_pair(&self) -> libsignal_protocol::error::Result<IdentityKeyPair> {
        Ok(self.identity.pair)
    }

    async fn get_local_registration_id(&self) -> libsignal_protocol::error::Result<u32> {
        Ok(self.identity.registration_id)
    }

    /// We never replace a pinned identity: a different key is an error, not an update.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> libsignal_protocol::error::Result<IdentityChange> {
        match self.get_identity(address).await? {
            Some(pinned) if pinned == *identity => Ok(IdentityChange::NewOrUnchanged),
            _ => Err(SignalProtocolError::UntrustedIdentity(address.clone())),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> libsignal_protocol::error::Result<bool> {
        Ok(self.get_identity(address).await?.is_some_and(|pinned| pinned == *identity))
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> libsignal_protocol::error::Result<Option<IdentityKey>> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT identity FROM signal_trusted WHERE address = ?1", [address.name()], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        row.map(|b| IdentityKey::decode(&b)).transpose()
    }
}

#[async_trait(?Send)]
impl SessionStore for Store<'_> {
    async fn load_session(&self, address: &ProtocolAddress) -> libsignal_protocol::error::Result<Option<SessionRecord>> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT record FROM signal_sessions WHERE address = ?1", [address.name()], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        let row = row.map(Zeroizing::new);
        row.map(|b| SessionRecord::deserialize(&b)).transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.conn
            .execute(
                "INSERT INTO signal_sessions (address, record) VALUES (?1, ?2)
                 ON CONFLICT(address) DO UPDATE SET record = excluded.record",
                params![address.name(), &*bytes],
            )
            .map_err(db_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for Store<'_> {
    async fn get_pre_key(&self, id: PreKeyId) -> libsignal_protocol::error::Result<PreKeyRecord> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT record FROM signal_prekeys WHERE id = ?1", [u32::from(id)], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        let row = Zeroizing::new(row.ok_or(SignalProtocolError::InvalidPreKeyId)?);
        PreKeyRecord::deserialize(&row)
    }

    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO signal_prekeys (id, record, created_at) VALUES (?1, ?2, ?3)",
                params![u32::from(id), &*bytes, now_secs()],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// One-time prekeys are erased as soon as they are used (forward secrecy).
    async fn remove_pre_key(&mut self, id: PreKeyId) -> libsignal_protocol::error::Result<()> {
        self.conn.execute("DELETE FROM signal_prekeys WHERE id = ?1", [u32::from(id)]).map_err(db_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for Store<'_> {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> libsignal_protocol::error::Result<SignedPreKeyRecord> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT record FROM signal_signed_prekeys WHERE id = ?1", [u32::from(id)], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        let row = Zeroizing::new(row.ok_or(SignalProtocolError::InvalidSignedPreKeyId)?);
        SignedPreKeyRecord::deserialize(&row)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO signal_signed_prekeys (id, record, created_at) VALUES (?1, ?2, ?3)",
                params![u32::from(id), &*bytes, now_secs()],
            )
            .map_err(db_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for Store<'_> {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> libsignal_protocol::error::Result<KyberPreKeyRecord> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT record FROM signal_kyber_prekeys WHERE id = ?1", [u32::from(id)], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        let row = Zeroizing::new(row.ok_or(SignalProtocolError::InvalidKyberPreKeyId)?);
        KyberPreKeyRecord::deserialize(&row)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO signal_kyber_prekeys (id, record, created_at) VALUES (?1, ?2, ?3)",
                params![u32::from(id), &*bytes, now_secs()],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// All our Kyber prekeys are one-time keys: erase on use. A replay of the same PreKey
    /// message then fails because the key is gone.
    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> libsignal_protocol::error::Result<()> {
        self.conn.execute("DELETE FROM signal_kyber_prekeys WHERE id = ?1", [u32::from(id)]).map_err(db_err)?;
        Ok(())
    }
}

fn db_err(e: rusqlite::Error) -> SignalProtocolError {
    SignalProtocolError::InvalidState("vault", e.to_string())
}

// ------------------------------------------------------------------- prekeys

/// Returns the current signed prekey, generating or rotating it when needed.
fn current_signed_prekey(conn: &Connection, identity: &Identity) -> Result<SignedPreKeyRecord> {
    let newest: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT record, created_at FROM signal_signed_prekeys ORDER BY created_at DESC, id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((rec, created)) = newest
        && now_secs() - created < SIGNED_PREKEY_ROTATE_AFTER.as_secs() as i64
    {
        let rec = Zeroizing::new(rec);
        return Ok(SignedPreKeyRecord::deserialize(&rec)?);
    }
    let mut r = rng();
    let pair = KeyPair::generate(&mut r);
    let sig = identity.pair.private_key().calculate_signature(&pair.public_key.serialize(), &mut r).map_err(SignalProtocolError::from)?;
    let id = unused_id(conn, "signal_signed_prekeys")?;
    let record = SignedPreKeyRecord::new(id.into(), Timestamp::from_epoch_millis(now_millis()), &pair, &sig);
    let mut store = Store { conn, identity };
    block_on(store.save_signed_pre_key(id.into(), &record))?;
    Ok(record)
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A random 31-bit id not yet used in `table`.
fn unused_id(conn: &Connection, table: &str) -> Result<u32> {
    let mut r = rng();
    loop {
        let id: u32 = r.random_range(1..0x7fff_ffff);
        let exists: bool =
            conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id = ?1)"), [id], |row| row.get(0))?;
        if !exists {
            return Ok(id);
        }
    }
}

/// Builds a fresh bundle for the peer: current signed prekey, plus a brand-new one-time EC
/// prekey and a brand-new one-time ML-KEM-1024 prekey (both erased when used).
pub fn new_bundle(conn: &Connection, identity: &Identity) -> Result<Bundle> {
    let spk = current_signed_prekey(conn, identity)?;
    // Bound storage: keep only the newest unused one-time keys. A bundle is requested once per
    // session setup, so legitimate use never comes close to this.
    for table in ["signal_prekeys", "signal_kyber_prekeys"] {
        conn.execute(
            &format!(
                "DELETE FROM {table} WHERE id NOT IN (SELECT id FROM {table} ORDER BY created_at DESC, rowid DESC LIMIT ?1)"
            ),
            [MAX_UNUSED_ONE_TIME_KEYS - 1],
        )?;
    }
    let mut r = rng();
    let mut store = Store { conn, identity };

    let otk = KeyPair::generate(&mut r);
    let otk_id = unused_id(conn, "signal_prekeys")?;
    block_on(store.save_pre_key(otk_id.into(), &PreKeyRecord::new(otk_id.into(), &otk)))?;

    let kyber_id = unused_id(conn, "signal_kyber_prekeys")?;
    let kyber = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, kyber_id.into(), identity.pair.private_key())?;
    block_on(store.save_kyber_pre_key(kyber_id.into(), &kyber))?;

    Ok(Bundle {
        registration_id: identity.registration_id,
        device_id: u32::from(device()),
        prekey_id: otk_id,
        prekey_pub: otk.public_key.serialize().to_vec(),
        signed_prekey_id: u32::from(spk.id()?),
        signed_prekey_pub: spk.public_key()?.serialize().to_vec(),
        signed_prekey_signature: spk.signature()?,
        kyber_prekey_id: kyber_id,
        kyber_prekey_pub: kyber.public_key()?.serialize().to_vec(),
        kyber_prekey_signature: kyber.signature()?,
        identity_key: identity.public_bytes(),
    })
}

/// Rotates the signed prekey if due and erases expired key material.
pub fn maintenance(conn: &Connection, identity: &Identity) -> Result<()> {
    current_signed_prekey(conn, identity)?;
    let now = now_secs();
    conn.execute(
        "DELETE FROM signal_signed_prekeys WHERE created_at < ?1
         AND id <> (SELECT id FROM signal_signed_prekeys ORDER BY created_at DESC, id DESC LIMIT 1)",
        [now - SIGNED_PREKEY_KEEP.as_secs() as i64],
    )?;
    let cutoff = now - ONE_TIME_PREKEY_KEEP.as_secs() as i64;
    conn.execute("DELETE FROM signal_prekeys WHERE created_at < ?1", [cutoff])?;
    conn.execute("DELETE FROM signal_kyber_prekeys WHERE created_at < ?1", [cutoff])?;
    Ok(())
}

// ------------------------------------------------------------------- sessions

/// Whether we hold a usable (non-stale, post-quantum) session with this peer.
pub fn has_session(conn: &Connection, identity: &Identity, peer_identity: &[u8]) -> Result<bool> {
    let store = Store { conn, identity };
    let addr = peer_address(peer_identity);
    Ok(match block_on(store.load_session(&addr))? {
        Some(rec) => rec.has_usable_sender_chain(SystemTime::now(), usable())?,
        None => false,
    })
}

/// Processes the peer's bundle (PQXDH). The bundle's identity key must equal the pinned one,
/// and libsignal verifies both prekey signatures against it.
pub fn start_session(conn: &Connection, identity: &Identity, peer_identity: &[u8], bundle: &Bundle) -> Result<()> {
    if bundle.identity_key != peer_identity {
        return Err(Error::UntrustedIdentity);
    }
    let ik = IdentityKey::decode(&bundle.identity_key)?;
    let pk = (
        PreKeyId::from(bundle.prekey_id),
        PublicKey::deserialize(&bundle.prekey_pub).map_err(|_| Error::BadBundle("prekey"))?,
    );
    let pre = PreKeyBundle::new(
        bundle.registration_id,
        DeviceId::try_from(bundle.device_id).map_err(|_| Error::BadBundle("device id"))?,
        Some(pk),
        bundle.signed_prekey_id.into(),
        PublicKey::deserialize(&bundle.signed_prekey_pub).map_err(|_| Error::BadBundle("signed prekey"))?,
        bundle.signed_prekey_signature.clone(),
        bundle.kyber_prekey_id.into(),
        kem::PublicKey::deserialize(&bundle.kyber_prekey_pub).map_err(|_| Error::BadBundle("kyber prekey"))?,
        bundle.kyber_prekey_signature.clone(),
        ik,
    )?;
    let addr = peer_address(peer_identity);
    let mut sessions = Store { conn, identity };
    let mut identities = Store { conn, identity };
    let r = block_on(libsignal_protocol::process_prekey_bundle(
        &addr,
        &local_address(),
        &mut sessions,
        &mut identities,
        &pre,
        SystemTime::now(),
        &mut rng(),
    ));
    match r {
        Err(SignalProtocolError::UntrustedIdentity(_)) => Err(Error::UntrustedIdentity),
        other => Ok(other?),
    }
}

/// Encrypts a (padded) plaintext for the peer. Returns (envelope kind, ciphertext).
pub fn encrypt(conn: &Connection, identity: &Identity, peer_identity: &[u8], plaintext: &[u8]) -> Result<(u32, Vec<u8>)> {
    let addr = peer_address(peer_identity);
    let mut sessions = Store { conn, identity };
    let mut identities = Store { conn, identity };
    let msg = block_on(libsignal_protocol::message_encrypt(
        plaintext,
        &addr,
        &local_address(),
        &mut sessions,
        &mut identities,
        SystemTime::now(),
        &mut rng(),
    ))
    .map_err(map_untrusted)?;
    let kind = match msg.message_type() {
        CiphertextMessageType::Whisper => ENVELOPE_WHISPER,
        CiphertextMessageType::PreKey => ENVELOPE_PREKEY,
        _ => return Err(Error::BadEnvelope),
    };
    Ok((kind, msg.serialize().to_vec()))
}

/// Decrypts an envelope from the peer. On any failure the stored session is unchanged
/// (libsignal only persists state after successful decryption).
pub fn decrypt(
    conn: &Connection,
    identity: &Identity,
    peer_identity: &[u8],
    kind: u32,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let msg = match kind {
        ENVELOPE_WHISPER => CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext)?),
        ENVELOPE_PREKEY => CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ciphertext)?),
        _ => return Err(Error::BadEnvelope),
    };
    let addr = peer_address(peer_identity);
    let mut s = Store { conn, identity };
    let mut i = Store { conn, identity };
    let mut p = Store { conn, identity };
    let sp = Store { conn, identity };
    let mut k = Store { conn, identity };
    // Run inside a savepoint: if anything fails half-way (e.g. prekey consumed but decryption
    // fails), roll every table back so a forged message cannot destroy key material.
    conn.execute_batch("SAVEPOINT signal_decrypt")?;
    let r = block_on(libsignal_protocol::message_decrypt(
        &msg,
        &addr,
        &local_address(),
        &mut s,
        &mut i,
        &mut p,
        &sp,
        &mut k,
        &mut rng(),
    ));
    match r {
        Ok(pt) => {
            conn.execute_batch("RELEASE signal_decrypt")?;
            Ok(Zeroizing::new(pt))
        }
        Err(e) => {
            conn.execute_batch("ROLLBACK TO signal_decrypt; RELEASE signal_decrypt")?;
            Err(map_untrusted(e))
        }
    }
}

fn map_untrusted(e: SignalProtocolError) -> Error {
    match e {
        SignalProtocolError::UntrustedIdentity(_) => Error::UntrustedIdentity,
        e => Error::Signal(e),
    }
}

// ------------------------------------------------------------------- padding

const PAD_BLOCK: usize = 160;

/// Signal-style padding: `plaintext || 0x80 || 0x00…` up to a multiple of 160 bytes.
pub fn pad(plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
    let len = (plaintext.len() + 1).div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(len, 0);
    out
}

pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let end = padded.iter().rposition(|&b| b != 0).ok_or(Error::BadPadding)?;
    if padded[end] != 0x80 {
        return Err(Error::BadPadding);
    }
    Ok(&padded[..end])
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod robustness;
