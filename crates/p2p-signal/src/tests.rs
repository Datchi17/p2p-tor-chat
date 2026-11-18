use super::*;
use p2p_vault::{KdfParams, Vault};

const PASS: &str = "test passphrase long enough";

struct Party {
    _dir: tempfile::TempDir,
    vault: Vault,
    id: Identity,
}

fn party() -> Party {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), PASS, KdfParams::INSECURE_TEST_ONLY, &[SCHEMA]).unwrap();
    Party { _dir: dir, vault, id: Identity::generate() }
}

fn c(p: &Party) -> &Connection {
    p.vault.conn()
}

/// Alice and Bob paired (trusting each other), with Alice holding a session from Bob's bundle.
fn paired() -> (Party, Party) {
    let (a, b) = (party(), party());
    trust(c(&a), &b.id.public_bytes()).unwrap();
    trust(c(&b), &a.id.public_bytes()).unwrap();
    let bundle = new_bundle(c(&b), &b.id).unwrap();
    start_session(c(&a), &a.id, &b.id.public_bytes(), &bundle).unwrap();
    (a, b)
}

fn send(from: &Party, to: &Party, text: &[u8]) -> (u32, Vec<u8>) {
    encrypt(c(from), &from.id, &to.id.public_bytes(), &pad(text)).unwrap()
}

fn recv(to: &Party, from: &Party, env: &(u32, Vec<u8>)) -> Result<Vec<u8>> {
    let pt = decrypt(c(to), &to.id, &from.id.public_bytes(), env.0, &env.1)?;
    Ok(unpad(&pt)?.to_vec())
}

fn count(p: &Party, table: &str) -> i64 {
    c(p).query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)).unwrap()
}

#[test]
fn full_conversation_both_directions() {
    let (a, b) = paired();
    let m1 = send(&a, &b, b"hello bob");
    assert_eq!(m1.0, ENVELOPE_PREKEY, "first message carries the PQXDH header");
    assert_eq!(recv(&b, &a, &m1).unwrap(), b"hello bob");
    let r1 = send(&b, &a, b"hi alice");
    assert_eq!(r1.0, ENVELOPE_WHISPER);
    assert_eq!(recv(&a, &b, &r1).unwrap(), b"hi alice");
    // After a reply, Alice's messages are normal ratchet messages.
    let m2 = send(&a, &b, b"second");
    assert_eq!(m2.0, ENVELOPE_WHISPER);
    assert_eq!(recv(&b, &a, &m2).unwrap(), b"second");
    assert!(has_session(c(&a), &a.id, &b.id.public_bytes()).unwrap());
    assert!(has_session(c(&b), &b.id, &a.id.public_bytes()).unwrap());
}

#[test]
fn session_is_post_quantum() {
    let (a, b) = paired();
    let m1 = send(&a, &b, b"x");
    recv(&b, &a, &m1).unwrap();
    let store = Store { conn: c(&b), identity: &b.id };
    let rec = block_on(store.load_session(&peer_address(&a.id.public_bytes()))).unwrap().unwrap();
    assert!(rec.has_usable_sender_chain(SystemTime::now(), SessionUsabilityRequirements::EstablishedWithPqxdh).unwrap());
    assert!(rec.get_kyber_ciphertext().is_ok());
}

#[test]
fn one_time_prekeys_are_erased_after_use() {
    let (a, b) = paired();
    assert_eq!(count(&b, "signal_prekeys"), 1);
    assert_eq!(count(&b, "signal_kyber_prekeys"), 1);
    let m1 = send(&a, &b, b"x");
    recv(&b, &a, &m1).unwrap();
    assert_eq!(count(&b, "signal_prekeys"), 0);
    assert_eq!(count(&b, "signal_kyber_prekeys"), 0);
}

#[test]
fn replayed_prekey_message_is_rejected() {
    let (a, b) = paired();
    let m1 = send(&a, &b, b"once");
    recv(&b, &a, &m1).unwrap();
    assert!(recv(&b, &a, &m1).is_err(), "replay must fail");
}

#[test]
fn replayed_ratchet_message_is_rejected() {
    let (a, b) = paired();
    let m1 = send(&a, &b, b"x");
    recv(&b, &a, &m1).unwrap();
    let r = send(&b, &a, b"reply");
    recv(&a, &b, &r).unwrap();
    assert!(recv(&a, &b, &r).is_err(), "message keys are deleted after use");
}

#[test]
fn tampered_message_rejected_and_state_unchanged() {
    let (a, b) = paired();
    let m1 = send(&a, &b, b"x");
    recv(&b, &a, &m1).unwrap();
    let r1 = send(&b, &a, b"genuine");
    let mut forged = r1.clone();
    let last = forged.1.len() - 12;
    forged.1[last] ^= 0x01;
    assert!(recv(&a, &b, &forged).is_err());
    // The genuine message still decrypts: the forgery did not advance or corrupt state.
    assert_eq!(recv(&a, &b, &r1).unwrap(), b"genuine");
}

#[test]
fn forged_prekey_message_does_not_consume_prekeys() {
    let (a, b) = paired();
    let mut m1 = send(&a, &b, b"x");
    let last = m1.1.len() - 12;
    m1.1[last] ^= 0x01;
    assert!(recv(&b, &a, &m1).is_err());
    assert_eq!(count(&b, "signal_prekeys"), 1, "prekey must survive a forged message");
    assert_eq!(count(&b, "signal_kyber_prekeys"), 1);
    assert_eq!(count(&b, "signal_sessions"), 0);
}

#[test]
fn out_of_order_delivery() {
    let (a, b) = paired();
    let m1 = send(&a, &b, b"one");
    recv(&b, &a, &m1).unwrap();
    let r = send(&b, &a, b"ack");
    recv(&a, &b, &r).unwrap();
    let (x, y, z) = (send(&a, &b, b"x"), send(&a, &b, b"y"), send(&a, &b, b"z"));
    assert_eq!(recv(&b, &a, &z).unwrap(), b"z");
    assert_eq!(recv(&b, &a, &x).unwrap(), b"x");
    assert_eq!(recv(&b, &a, &y).unwrap(), b"y");
}

#[test]
fn impostor_bundle_is_rejected() {
    // Alice pinned Bob's real key, but receives a bundle from Mallory.
    let (a, b, m) = (party(), party(), party());
    trust(c(&a), &b.id.public_bytes()).unwrap();
    let mallory_bundle = new_bundle(c(&m), &m.id).unwrap();
    let err = start_session(c(&a), &a.id, &b.id.public_bytes(), &mallory_bundle).unwrap_err();
    assert!(matches!(err, Error::UntrustedIdentity), "{err:?}");
    // Even if Mallory lies about the identity field, the signatures won't verify.
    let mut lying = mallory_bundle;
    lying.identity_key = b.id.public_bytes();
    assert!(start_session(c(&a), &a.id, &b.id.public_bytes(), &lying).is_err());
}

#[test]
fn message_from_unpinned_identity_is_rejected() {
    // Bob never trusted Mallory: Mallory's PreKey message must not create a session.
    let (b, m) = (party(), party());
    trust(c(&m), &b.id.public_bytes()).unwrap();
    let bundle = new_bundle(c(&b), &b.id).unwrap();
    start_session(c(&m), &m.id, &b.id.public_bytes(), &bundle).unwrap();
    let env = send(&m, &b, b"evil");
    assert!(recv(&b, &m, &env).is_err());
    assert_eq!(count(&b, "signal_sessions"), 0);
}

#[test]
fn safety_numbers_match_on_both_sides() {
    let (a, b) = (Identity::generate(), Identity::generate());
    let sa = safety_number(&a.public_bytes(), &b.public_bytes()).unwrap();
    let sb = safety_number(&b.public_bytes(), &a.public_bytes()).unwrap();
    assert_eq!(sa, sb);
    assert_eq!(sa.len(), 60);
    assert!(sa.chars().all(|ch| ch.is_ascii_digit()));
    let other = Identity::generate();
    assert_ne!(sa, safety_number(&a.public_bytes(), &other.public_bytes()).unwrap());
}

#[test]
fn identity_roundtrip_and_signatures() {
    let id = Identity::generate();
    let back = Identity::from_bytes(&id.to_bytes()).unwrap();
    assert_eq!(back.public_bytes(), id.public_bytes());
    let sig = id.sign(b"ctx", b"msg").unwrap();
    assert!(verify_signature(&id.public_bytes(), b"ctx", b"msg", &sig));
    assert!(!verify_signature(&id.public_bytes(), b"other-ctx", b"msg", &sig));
    assert!(!verify_signature(&id.public_bytes(), b"ctx", b"msG", &sig));
}

#[test]
fn signed_prekey_rotation_and_cleanup() {
    let p = party();
    new_bundle(c(&p), &p.id).unwrap();
    assert_eq!(count(&p, "signal_signed_prekeys"), 1);
    // Age everything by 40 days: rotation creates a new signed prekey, cleanup removes the old
    // one and the unused one-time keys.
    c(&p).execute_batch(
        "UPDATE signal_signed_prekeys SET created_at = created_at - 3456000;
         UPDATE signal_prekeys SET created_at = created_at - 3456000;
         UPDATE signal_kyber_prekeys SET created_at = created_at - 3456000;",
    )
    .unwrap();
    maintenance(c(&p), &p.id).unwrap();
    assert_eq!(count(&p, "signal_signed_prekeys"), 1);
    assert_eq!(count(&p, "signal_prekeys"), 0);
    assert_eq!(count(&p, "signal_kyber_prekeys"), 0);
}

#[test]
fn padding_roundtrip() {
    for n in [0usize, 1, 158, 159, 160, 1000] {
        let data = vec![0xAB; n];
        let p = pad(&data);
        assert_eq!(p.len() % PAD_BLOCK, 0);
        assert_eq!(unpad(&p).unwrap(), &data[..]);
    }
    assert!(unpad(&[0, 0, 0]).is_err());
    assert!(unpad(&[1, 2, 3]).is_err());
}

#[test]
fn prekey_message_overhead_is_bounded() {
    // p2p-core relies on this bound to size file chunks so an envelope always fits one frame.
    let (a, b) = paired();
    let pt = vec![0x5a; 50_000];
    let padded = pad(&pt).len();
    let (kind, ct) = send(&a, &b, &pt);
    assert_eq!(kind, ENVELOPE_PREKEY);
    let overhead = ct.len() - padded;
    eprintln!("PreKey overhead: {overhead} bytes");
    assert!(overhead < 4096, "{overhead}");
    assert_eq!(recv(&b, &a, &(kind, ct)).unwrap(), pt);
}
