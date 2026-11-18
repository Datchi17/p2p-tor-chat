//! Tor v3 onion addresses and client-authorization keys.

use data_encoding::BASE32_NOPAD;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Length of a v3 onion service ID (address without the `.onion` suffix).
pub const SERVICE_ID_LEN: usize = 56;

/// A validated v3 onion service ID (56 lowercase base32 characters, no `.onion`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServiceId(String);

impl std::fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServiceId({}…)", &self.0[..8])
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OnionError {
    #[error("onion address must be 56 base32 characters")]
    BadLength,
    #[error("onion address is not valid base32")]
    BadEncoding,
    #[error("unsupported onion address version")]
    BadVersion,
    #[error("onion address checksum mismatch")]
    BadChecksum,
}

impl ServiceId {
    /// Parses and fully validates a v3 onion address (with or without `.onion`):
    /// `base32(pubkey[32] || checksum[2] || version[1])`, where
    /// `checksum = SHA3-256(".onion checksum" || pubkey || version)[..2]`.
    pub fn parse(s: &str) -> Result<ServiceId, OnionError> {
        let s = s.trim().to_ascii_lowercase();
        let id = s.strip_suffix(".onion").unwrap_or(&s);
        if id.len() != SERVICE_ID_LEN {
            return Err(OnionError::BadLength);
        }
        let raw = BASE32_NOPAD
            .decode(id.to_ascii_uppercase().as_bytes())
            .map_err(|_| OnionError::BadEncoding)?;
        if raw.len() != 35 {
            return Err(OnionError::BadLength);
        }
        let (pubkey, rest) = raw.split_at(32);
        let (checksum, version) = rest.split_at(2);
        if version != [3] {
            return Err(OnionError::BadVersion);
        }
        let mut h = Sha3_256::new();
        h.update(b".onion checksum");
        h.update(pubkey);
        h.update(version);
        if h.finalize()[..2] != *checksum {
            return Err(OnionError::BadChecksum);
        }
        Ok(ServiceId(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Onion address for an ed25519 public key (rend-spec-v3 §6).
    pub fn from_public_key(pubkey: &[u8; 32]) -> ServiceId {
        let mut h = Sha3_256::new();
        h.update(b".onion checksum");
        h.update(pubkey);
        h.update([3u8]);
        let checksum = h.finalize();
        let mut raw = Vec::with_capacity(35);
        raw.extend_from_slice(pubkey);
        raw.extend_from_slice(&checksum[..2]);
        raw.push(3);
        ServiceId(BASE32_NOPAD.encode(&raw).to_ascii_lowercase())
    }

    /// `xxxx.onion`, as used in SOCKS connect requests.
    pub fn hostname(&self) -> String {
        format!("{}.onion", self.0)
    }
}

/// An x25519 keypair for Tor v3 onion-service client authorization.
pub struct ClientAuthKey {
    secret: StaticSecret,
}

impl ClientAuthKey {
    pub fn generate() -> ClientAuthKey {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).expect("OS RNG unavailable");
        ClientAuthKey { secret: StaticSecret::from(*bytes) }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> ClientAuthKey {
        ClientAuthKey { secret: StaticSecret::from(bytes) }
    }

    /// Secret key bytes, for storage in the encrypted vault only.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }
}

/// Tor's `ClientAuthV3=` format: base32 (no padding) of the x25519 public key.
pub fn client_auth_pub_base32(public: &[u8; 32]) -> String {
    BASE32_NOPAD.encode(public)
}

/// Generates an onion-service identity locally, without Tor: a random ed25519 seed, expanded
/// exactly like Tor does (SHA-512, then clamping), returned as the 64-byte expanded secret in
/// Tor's control-port format `ED25519-V3:<base64>` together with its onion address.
pub fn generate_onion_identity() -> (Zeroizing<String>, ServiceId) {
    use base64::Engine as _;
    use sha2::Digest as _;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).expect("OS RNG unavailable");
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mut expanded = Zeroizing::new([0u8; 64]);
    expanded.copy_from_slice(&sha2::Sha512::digest(seed.as_ref()));
    expanded[0] &= 248;
    expanded[31] &= 63;
    expanded[31] |= 64;
    let mut blob = Zeroizing::new(String::with_capacity(11 + 88));
    blob.push_str("ED25519-V3:");
    base64::engine::general_purpose::STANDARD.encode_string(expanded.as_ref(), &mut blob);
    (blob, ServiceId::from_public_key(&public))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Tor Project's own v3 onion address (public, well-known).
    const TORPROJECT: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    #[test]
    fn parses_real_address() {
        let id = ServiceId::parse(TORPROJECT).unwrap();
        assert_eq!(id.hostname(), TORPROJECT);
        assert_eq!(ServiceId::parse(&TORPROJECT.to_uppercase()).unwrap(), id);
    }

    #[test]
    fn rejects_bad_checksum_and_length() {
        let mut bad = TORPROJECT.to_string();
        bad.replace_range(10..11, if &bad[10..11] == "a" { "b" } else { "a" });
        assert!(ServiceId::parse(&bad).is_err());
        assert_eq!(ServiceId::parse("abc.onion"), Err(OnionError::BadLength));
        assert_eq!(ServiceId::parse(&"1".repeat(56)), Err(OnionError::BadEncoding));
    }

    #[test]
    fn generated_identity_has_valid_address() {
        let (blob, id) = generate_onion_identity();
        assert!(blob.starts_with("ED25519-V3:"));
        assert_eq!(blob.len(), 11 + 88);
        assert_eq!(ServiceId::parse(id.as_str()).unwrap(), id);
    }

    #[test]
    fn client_auth_roundtrip() {
        let k = ClientAuthKey::generate();
        let k2 = ClientAuthKey::from_bytes(*k.secret_bytes());
        assert_eq!(k.public_bytes(), k2.public_bytes());
        assert_eq!(client_auth_pub_base32(&k.public_bytes()).len(), 52);
    }
}
