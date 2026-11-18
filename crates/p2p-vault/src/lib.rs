//! Passphrase-protected encrypted storage.
//!
//! The vault is a SQLCipher database whose 256-bit key is derived from the
//! user's passphrase with Argon2id. The key never touches disk; only the salt
//! and KDF parameters are stored next to the database (they are not secret).
//!
//! Files inside the vault directory:
//! - `vault.json` — format version, Argon2id salt and parameters
//! - `vault.db`   — SQLCipher database (AES-256, HMAC-SHA512 page authentication)
//! - `vault.lock` — advisory lock so two app instances never open the same vault

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub use rusqlite;

const HEADER_FILE: &str = "vault.json";
const PENDING_HEADER_FILE: &str = "vault.json.pending";
const DB_FILE: &str = "vault.db";
const LOCK_FILE: &str = "vault.lock";
const FORMAT_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Minimum accepted passphrase length (characters). The UI recommends far more.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("wrong passphrase or corrupted vault")]
    WrongPassphrase,
    #[error("a vault already exists in this location")]
    AlreadyExists,
    #[error("no vault found in this location")]
    NotFound,
    #[error("the vault is already open in another instance of the app")]
    Locked,
    #[error("passphrase must be at least {MIN_PASSPHRASE_CHARS} characters")]
    PassphraseTooShort,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid vault header: {0}")]
    Header(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// Production parameters: 256 MiB, 3 passes, 4 lanes (~0.5–1.5 s on a desktop).
    pub const STRONG: KdfParams = KdfParams { m_cost: 256 * 1024, t_cost: 3, p_cost: 4 };

    /// Tiny parameters, only for tests.
    #[doc(hidden)]
    pub const INSECURE_TEST_ONLY: KdfParams = KdfParams { m_cost: 8, t_cost: 1, p_cost: 1 };

    /// The weakest parameters we accept when opening an existing vault, so a
    /// tampered `vault.json` cannot silently downgrade the KDF.
    const FLOOR: KdfParams = KdfParams { m_cost: 64 * 1024, t_cost: 2, p_cost: 1 };
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    version: u32,
    salt: String,
    kdf: KdfParams,
}

/// An open, unlocked vault.
pub struct Vault {
    dir: PathBuf,
    conn: Connection,
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    // Held for the lifetime of the vault; dropping it releases the OS lock.
    _lock: File,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("dir", &self.dir).finish_non_exhaustive()
    }
}

/// Returns true if a vault exists in `dir`.
pub fn exists(dir: &Path) -> bool {
    dir.join(HEADER_FILE).is_file() && dir.join(DB_FILE).is_file()
}

fn derive_key(passphrase: &str, salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(key)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

fn acquire_lock(dir: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_FILE))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(VaultError::Locked),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// SQLCipher raw-key literal `x'<hex>'`. Raw keys bypass SQLCipher's own PBKDF2, since
/// Argon2id already did the work. The buffer is sized up front so it never reallocates
/// (a reallocation would leave an unwiped copy of the key on the heap).
fn key_literal(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = Zeroizing::new(String::with_capacity(KEY_LEN * 2 + 3));
    s.push_str("x'");
    for b in key {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s.push('\'');
    debug_assert_eq!(s.capacity(), KEY_LEN * 2 + 3);
    s
}

/// Opens a SQLCipher connection with a raw 256-bit key and hardened pragmas.
fn open_connection(path: &Path, key: &[u8; KEY_LEN]) -> Result<Connection> {
    let conn = Connection::open(path)?;
    // Keep SQLCipher quiet on stderr (it logs every failed page decryption).
    conn.pragma_update(None, "cipher_log_level", "NONE")?;
    conn.pragma_update(None, "key", &*key_literal(key))?;
    // Wipe SQLCipher's internal buffers on free.
    conn.pragma_update(None, "cipher_memory_security", "ON")?;
    // Overwrite deleted rows instead of leaving them in free pages.
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // Temp tables/indices stay in RAM, never in unencrypted temp files.
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    // Touching the schema is the first operation that needs the key: a wrong key fails here.
    let check: rusqlite::Result<i64> =
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0));
    match check {
        Ok(_) => Ok(conn),
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::NotADatabase => {
            Err(VaultError::WrongPassphrase)
        }
        Err(e) => Err(e.into()),
    }
}

/// Applies `migrations` in order, tracking progress with `PRAGMA user_version`.
fn migrate(conn: &mut Connection, migrations: &[&str]) -> Result<()> {
    let current: usize = conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? as usize;
    for (i, sql) in migrations.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

fn write_header(dir: &Path, header: &Header) -> Result<()> {
    write_header_as(dir, HEADER_FILE, header)
}

/// Writes a header durably: temp file, fsync, atomic rename.
fn write_header_as(dir: &Path, name: &str, header: &Header) -> Result<()> {
    let json = serde_json::to_vec_pretty(header).map_err(|e| VaultError::Header(e.to_string()))?;
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    fs::rename(tmp, dir.join(name))?;
    Ok(())
}

fn read_header(dir: &Path, name: &str) -> Result<(Header, [u8; SALT_LEN])> {
    let raw = fs::read(dir.join(name)).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => VaultError::NotFound,
        _ => e.into(),
    })?;
    let header: Header = serde_json::from_slice(&raw).map_err(|e| VaultError::Header(e.to_string()))?;
    if header.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(header.version));
    }
    let k = header.kdf;
    if k.m_cost < KdfParams::FLOOR.m_cost || k.t_cost < KdfParams::FLOOR.t_cost || k.p_cost < 1 {
        // Tests create vaults with tiny parameters; allow them only in test builds.
        if !(cfg!(test) || cfg!(feature = "insecure-test-params")) || k != KdfParams::INSECURE_TEST_ONLY {
            return Err(VaultError::Header("KDF parameters below the accepted minimum".into()));
        }
    }
    let salt_vec = B64.decode(&header.salt).map_err(|e| VaultError::Header(e.to_string()))?;
    let salt: [u8; SALT_LEN] =
        salt_vec.try_into().map_err(|_| VaultError::Header("bad salt length".into()))?;
    Ok((header, salt))
}

fn check_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(VaultError::PassphraseTooShort);
    }
    Ok(())
}

impl Vault {
    /// Creates a new vault in `dir` (created if missing) and applies `migrations`.
    pub fn create(dir: &Path, passphrase: &str, kdf: KdfParams, migrations: &[&str]) -> Result<Vault> {
        check_passphrase(passphrase)?;
        fs::create_dir_all(dir)?;
        restrict_dir_permissions(dir)?;
        let lock = acquire_lock(dir)?;
        if exists(dir) || dir.join(DB_FILE).exists() {
            return Err(VaultError::AlreadyExists);
        }
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key(passphrase, &salt, kdf)?;
        let mut conn = open_connection(&dir.join(DB_FILE), &key)?;
        migrate(&mut conn, migrations)?;
        // Write the header last so a crash mid-creation never leaves a "valid-looking" vault.
        write_header(dir, &Header { version: FORMAT_VERSION, salt: B64.encode(salt), kdf })?;
        Ok(Vault { dir: dir.to_path_buf(), conn, key, salt, kdf, _lock: lock })
    }

    /// Opens an existing vault. Fails with [`VaultError::WrongPassphrase`] on a bad passphrase.
    pub fn open(dir: &Path, passphrase: &str, migrations: &[&str]) -> Result<Vault> {
        if !exists(dir) {
            return Err(VaultError::NotFound);
        }
        let lock = acquire_lock(dir)?;
        let pending = dir.join(PENDING_HEADER_FILE);
        let (header, salt, key, mut conn) = match Self::try_header(dir, HEADER_FILE, passphrase) {
            Ok(opened) => {
                // A leftover pending header means a passphrase change never started re-keying.
                let _ = fs::remove_file(&pending);
                opened
            }
            Err(VaultError::WrongPassphrase) if pending.is_file() => {
                // Crash between re-key and rename: the database already uses the pending header.
                let opened = Self::try_header(dir, PENDING_HEADER_FILE, passphrase)?;
                fs::rename(&pending, dir.join(HEADER_FILE))?;
                opened
            }
            Err(e) => return Err(e),
        };
        migrate(&mut conn, migrations)?;
        Ok(Vault { dir: dir.to_path_buf(), conn, key, salt, kdf: header.kdf, _lock: lock })
    }

    #[allow(clippy::type_complexity)]
    fn try_header(
        dir: &Path,
        header_name: &str,
        passphrase: &str,
    ) -> Result<(Header, [u8; SALT_LEN], Zeroizing<[u8; KEY_LEN]>, Connection)> {
        let (header, salt) = read_header(dir, header_name)?;
        let key = derive_key(passphrase, &salt, header.kdf)?;
        let conn = open_connection(&dir.join(DB_FILE), &key)?;
        Ok((header, salt, key, conn))
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Checks a passphrase against the open vault in constant time (used by the lock screen).
    pub fn verify_passphrase(&self, passphrase: &str) -> bool {
        match derive_key(passphrase, &self.salt, self.kdf) {
            Ok(candidate) => bool::from(candidate.as_ref().ct_eq(self.key.as_ref())),
            Err(_) => false,
        }
    }

    /// Re-encrypts the whole database under a key derived from `new_passphrase`.
    ///
    /// Crash safety: the new header is written to `vault.json.pending` *before* the database
    /// is re-keyed, then atomically renamed over `vault.json`. If the app dies in between,
    /// [`Vault::open`] finds the pending header and finishes the switch.
    pub fn change_passphrase(&mut self, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        if !self.verify_passphrase(old_passphrase) {
            return Err(VaultError::WrongPassphrase);
        }
        check_passphrase(new_passphrase)?;
        let salt = random_bytes::<SALT_LEN>();
        let new_key = derive_key(new_passphrase, &salt, self.kdf)?;
        let header = Header { version: FORMAT_VERSION, salt: B64.encode(salt), kdf: self.kdf };
        write_header_as(&self.dir, PENDING_HEADER_FILE, &header)?;
        // When a rekey fails, SQLCipher rolls the transaction back but keeps encrypting later
        // writes on that connection with the *new* key, while the file stays under the old
        // one: anything saved afterwards would make the vault unreadable. So after a failure,
        // reconnect with the old key, and retry once on the clean connection.
        let db = self.dir.join(DB_FILE);
        let mut result = Ok(());
        for _ in 0..2 {
            result = self.conn.pragma_update(None, "rekey", &*key_literal(&new_key));
            if result.is_ok() {
                break;
            }
            match open_connection(&db, &self.key) {
                Ok(conn) => self.conn = conn,
                Err(e) => {
                    let _ = fs::remove_file(self.dir.join(PENDING_HEADER_FILE));
                    return Err(e);
                }
            }
        }
        if let Err(e) = result {
            let _ = fs::remove_file(self.dir.join(PENDING_HEADER_FILE));
            return Err(e.into());
        }
        fs::rename(self.dir.join(PENDING_HEADER_FILE), self.dir.join(HEADER_FILE))?;
        self.key = new_key;
        self.salt = salt;
        Ok(())
    }

    /// Closes the vault, wiping the key from memory.
    pub fn close(self) {
        drop(self);
    }

    /// Irreversibly destroys the vault: overwrites the database with random data, then deletes
    /// every vault file. Note: on SSDs and copy-on-write filesystems overwriting is best effort;
    /// the data is still unreadable without the passphrase-derived key.
    pub fn destroy(self) -> Result<()> {
        let dir = self.dir.clone();
        drop(self);
        destroy_dir_contents(&dir)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

/// Destroys a vault without opening it (panic wipe when locked or passphrase forgotten).
pub fn destroy_dir_contents(dir: &Path) -> Result<()> {
    for name in [DB_FILE, "vault.db-journal", "vault.db-wal", "vault.db-shm", HEADER_FILE, PENDING_HEADER_FILE] {
        let path = dir.join(name);
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(mut f) = OpenOptions::new().write(true).open(&path) {
                let mut remaining = meta.len();
                let mut chunk = vec![0u8; 64 * 1024];
                while remaining > 0 {
                    let n = remaining.min(chunk.len() as u64) as usize;
                    getrandom::fill(&mut chunk[..n]).expect("OS RNG unavailable");
                    if f.write_all(&chunk[..n]).is_err() {
                        break;
                    }
                    remaining -= n as u64;
                }
                let _ = f.sync_all();
            }
            fs::remove_file(&path)?;
        }
    }
    let _ = fs::remove_file(dir.join(LOCK_FILE));
    Ok(())
}

#[cfg(unix)]
fn restrict_dir_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_dir: &Path) -> Result<()> {
    // On Windows the per-user %APPDATA% directory is already private to the user account.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIGRATIONS: &[&str] = &[
        "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL);",
        "ALTER TABLE t ADD COLUMN extra INTEGER;",
    ];
    const PASS: &str = "correct horse battery staple";
    const P: KdfParams = KdfParams::INSECURE_TEST_ONLY;

    #[test]
    fn create_reopen_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        {
            let v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
            v.conn().execute("INSERT INTO t (v, extra) VALUES ('secret', 1)", []).unwrap();
        }
        let v = Vault::open(dir.path(), PASS, MIGRATIONS).unwrap();
        let s: String = v.conn().query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(s, "secret");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
        let err = Vault::open(dir.path(), "not the right passphrase", MIGRATIONS).unwrap_err();
        assert!(matches!(err, VaultError::WrongPassphrase), "{err:?}");
    }

    #[test]
    fn database_file_contains_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        {
            let v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
            v.conn().execute("INSERT INTO t (v) VALUES ('VERY-RECOGNIZABLE-PLAINTEXT')", []).unwrap();
        }
        let raw = fs::read(dir.path().join(DB_FILE)).unwrap();
        let needle = b"VERY-RECOGNIZABLE-PLAINTEXT";
        assert!(!raw.windows(needle.len()).any(|w| w == needle));
        assert!(!raw.starts_with(b"SQLite format 3"));
    }

    #[test]
    fn second_instance_cannot_open() {
        let dir = tempfile::tempdir().unwrap();
        let _v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
        let err = Vault::open(dir.path(), PASS, MIGRATIONS).unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
    }

    #[test]
    fn cannot_create_twice() {
        let dir = tempfile::tempdir().unwrap();
        drop(Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap());
        let err = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap_err();
        assert!(matches!(err, VaultError::AlreadyExists), "{err:?}");
    }

    #[test]
    fn short_passphrase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = Vault::create(dir.path(), "short", P, MIGRATIONS).unwrap_err();
        assert!(matches!(err, VaultError::PassphraseTooShort));
    }

    #[test]
    fn verify_passphrase_works() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
        assert!(v.verify_passphrase(PASS));
        assert!(!v.verify_passphrase("something else entirely"));
    }

    #[test]
    fn failed_rekey_keeps_the_vault_consistent() {
        // SQLCipher's rekey leaves the connection writing with the *new* key when it fails.
        // Force a failure (another connection holds the write lock) and check that data
        // written afterwards is still readable with the old passphrase after reopening.
        let dir = tempfile::tempdir().unwrap();
        let new_pass = "a completely different passphrase";
        {
            let mut v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
            let blocker = open_connection(&dir.path().join(DB_FILE), &v.key).unwrap();
            blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
            assert!(v.change_passphrase(PASS, new_pass).is_err());
            blocker.execute_batch("ROLLBACK").unwrap();
            drop(blocker);
            assert!(!dir.path().join(PENDING_HEADER_FILE).exists());
            for i in 0..200 {
                v.conn().execute("INSERT INTO t (v) VALUES (?1)", [format!("after failed rekey {i} {}", "x".repeat(200))]).unwrap();
            }
        }
        let v = Vault::open(dir.path(), PASS, MIGRATIONS).unwrap();
        let n: i64 = v.conn().query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 200);
        drop(v);
        assert!(matches!(Vault::open(dir.path(), new_pass, MIGRATIONS), Err(VaultError::WrongPassphrase)));
    }

    #[test]
    fn change_passphrase_reencrypts() {
        let dir = tempfile::tempdir().unwrap();
        let new_pass = "a completely different passphrase";
        {
            let mut v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
            v.conn().execute("INSERT INTO t (v) VALUES ('kept')", []).unwrap();
            assert!(matches!(
                v.change_passphrase("wrong old passphrase", new_pass),
                Err(VaultError::WrongPassphrase)
            ));
            v.change_passphrase(PASS, new_pass).unwrap();
        }
        assert!(matches!(Vault::open(dir.path(), PASS, MIGRATIONS), Err(VaultError::WrongPassphrase)));
        let v = Vault::open(dir.path(), new_pass, MIGRATIONS).unwrap();
        let s: String = v.conn().query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(s, "kept");
    }

    #[test]
    fn crash_during_passphrase_change_is_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let new_pass = "the brand new passphrase";
        let old_header = {
            let mut v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
            v.conn().execute("INSERT INTO t (v) VALUES ('survives')", []).unwrap();
            let old = fs::read(dir.path().join(HEADER_FILE)).unwrap();
            v.change_passphrase(PASS, new_pass).unwrap();
            old
        };
        // Simulate a crash after re-key but before the rename: pending holds the new header,
        // vault.json still holds the old one.
        fs::rename(dir.path().join(HEADER_FILE), dir.path().join(PENDING_HEADER_FILE)).unwrap();
        fs::write(dir.path().join(HEADER_FILE), old_header).unwrap();
        let v = Vault::open(dir.path(), new_pass, MIGRATIONS).unwrap();
        let s: String = v.conn().query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(s, "survives");
        assert!(!dir.path().join(PENDING_HEADER_FILE).exists());
    }

    #[test]
    fn migrations_are_incremental() {
        let dir = tempfile::tempdir().unwrap();
        drop(Vault::create(dir.path(), PASS, P, &MIGRATIONS[..1]).unwrap());
        let v = Vault::open(dir.path(), PASS, MIGRATIONS).unwrap();
        v.conn().execute("INSERT INTO t (v, extra) VALUES ('x', 2)", []).unwrap();
        let ver: i64 = v.conn().pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(ver, 2);
    }

    #[test]
    fn kdf_downgrade_in_header_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        drop(Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap());
        let (mut h, _) = read_header(dir.path(), HEADER_FILE).unwrap();
        h.kdf = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        write_header(dir.path(), &h).unwrap();
        let err = Vault::open(dir.path(), PASS, MIGRATIONS).unwrap_err();
        assert!(matches!(err, VaultError::Header(_)), "{err:?}");
    }

    #[test]
    fn destroy_removes_everything() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::create(dir.path(), PASS, P, MIGRATIONS).unwrap();
        v.destroy().unwrap();
        assert!(!exists(dir.path()));
        assert!(!dir.path().join(DB_FILE).exists());
    }
}

#[cfg(test)]
mod kdf_timing {
    /// `cargo test --release -- --ignored kdf_strong_timing --nocapture`
    #[test]
    #[ignore]
    fn kdf_strong_timing() {
        let t = std::time::Instant::now();
        let _ = super::derive_key("benchmark passphrase", &[7u8; 16], super::KdfParams::STRONG).unwrap();
        eprintln!("Argon2id STRONG took {:?}", t.elapsed());
    }
}
