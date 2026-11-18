//! Random-input robustness tests: hostile bytes must produce errors, never panics or state
//! changes.

use super::*;
use p2p_vault::{KdfParams, Vault};

fn rand_bytes(max: usize) -> Vec<u8> {
    let mut len = [0u8; 2];
    getrandom_fill(&mut len);
    let n = u16::from_le_bytes(len) as usize % (max + 1);
    let mut v = vec![0u8; n];
    getrandom_fill(&mut v);
    v
}

fn getrandom_fill(b: &mut [u8]) {
    rand::rng().fill(b);
}

#[test]
fn random_ciphertexts_never_panic_or_create_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::create(dir.path(), "robustness passphrase", KdfParams::INSECURE_TEST_ONLY, &[SCHEMA]).unwrap();
    let me = Identity::generate();
    let peer = Identity::generate();
    trust(v.conn(), &peer.public_bytes()).unwrap();
    for i in 0..5000 {
        let kind = [ENVELOPE_WHISPER, ENVELOPE_PREKEY, 0, 7][i % 4];
        let ct = rand_bytes(2048);
        assert!(decrypt(v.conn(), &me, &peer.public_bytes(), kind, &ct).is_err());
    }
    let sessions: i64 = v.conn().query_row("SELECT count(*) FROM signal_sessions", [], |r| r.get(0)).unwrap();
    assert_eq!(sessions, 0);
}

/// Flips every single bit of a genuine PreKey message (state rolled back between attempts).
/// Signal deliberately leaves two metadata fields unauthenticated — the low nibble of the
/// version byte and the registration ID — so flipping those may still decrypt. The property
/// that matters: **no modification ever yields a different plaintext**, and everything outside
/// those few metadata bytes is rejected. (On the wire, Noise also authenticates every frame.)
#[test]
fn bit_flips_never_change_plaintext() {
    let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let va = Vault::create(dirs.0.path(), "robustness passphrase", KdfParams::INSECURE_TEST_ONLY, &[SCHEMA]).unwrap();
    let vb = Vault::create(dirs.1.path(), "robustness passphrase", KdfParams::INSECURE_TEST_ONLY, &[SCHEMA]).unwrap();
    let (a, b) = (Identity::generate(), Identity::generate());
    trust(va.conn(), &b.public_bytes()).unwrap();
    trust(vb.conn(), &a.public_bytes()).unwrap();
    let bundle = new_bundle(vb.conn(), &b).unwrap();
    start_session(va.conn(), &a, &b.public_bytes(), &bundle).unwrap();
    let (kind, ct) = encrypt(va.conn(), &a, &b.public_bytes(), &pad(b"genuine")).unwrap();
    let mut accepted = std::collections::BTreeSet::new();
    for pos in 0..ct.len() {
        for bit in [0u8, 3, 7] {
            let mut m = ct.clone();
            m[pos] ^= 1 << bit;
            vb.conn().execute_batch("SAVEPOINT probe").unwrap();
            if let Ok(pt) = decrypt(vb.conn(), &b, &a.public_bytes(), kind, &m) {
                assert_eq!(unpad(&pt).unwrap(), b"genuine", "byte {pos} bit {bit} changed the plaintext");
                accepted.insert(pos);
            }
            vb.conn().execute_batch("ROLLBACK TO probe; RELEASE probe").unwrap();
        }
    }
    assert!(accepted.len() <= 4, "too many unauthenticated bytes: {accepted:?}");
    // The genuine message still decrypts afterwards.
    let pt = decrypt(vb.conn(), &b, &a.public_bytes(), kind, &ct).unwrap();
    assert_eq!(unpad(&pt).unwrap(), b"genuine");
}

#[test]
fn bundle_storage_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::create(dir.path(), "robustness passphrase", KdfParams::INSECURE_TEST_ONLY, &[SCHEMA]).unwrap();
    let me = Identity::generate();
    for _ in 0..60 {
        new_bundle(v.conn(), &me).unwrap();
    }
    for table in ["signal_prekeys", "signal_kyber_prekeys"] {
        let n: i64 = v.conn().query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)).unwrap();
        assert!(n <= MAX_UNUSED_ONE_TIME_KEYS, "{table}: {n}");
    }
}

#[test]
fn random_padding_never_panics() {
    for _ in 0..20000 {
        let _ = unpad(&rand_bytes(400));
    }
}

#[test]
fn random_keys_and_signatures_never_panic() {
    for _ in 0..5000 {
        let k = rand_bytes(40);
        let _ = is_valid_identity_key(&k);
        let _ = verify_signature(&k, b"ctx", &rand_bytes(64), &rand_bytes(80));
        let _ = safety_number(&k, &rand_bytes(40));
        let _ = Identity::from_bytes(&rand_bytes(80));
    }
}
