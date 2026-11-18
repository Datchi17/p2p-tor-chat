//! Offline tests (no Tor): vault lifecycle, pairing, contacts, outbox. The networked
//! end-to-end test is in `tests/e2e_live.rs`.

use super::*;

fn core(dir: &std::path::Path) -> Core {
    Core::new(Config {
        data_dir: dir.to_path_buf(),
        // Point at a non-existent Tor so networking stays off in offline tests.
        tor_binary: Some(dir.join("no-tor-here")),
        pt_binary: None,
        kdf: KdfParams::INSECURE_TEST_ONLY,
    })
}

fn pass() -> Zeroizing<String> {
    Zeroizing::new("correct horse battery staple".to_string())
}

#[tokio::test]
async fn lifecycle_create_lock_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(dir.path());
    assert_eq!(c.state(), AppState::NoVault);
    c.create_vault("Datchi", pass()).await.unwrap();
    assert_eq!(c.state(), AppState::Unlocked);
    let code1 = c.my_code().unwrap();
    c.lock().await;
    assert_eq!(c.state(), AppState::Locked);
    assert!(matches!(c.my_code(), Err(CoreError::Locked)));
    assert!(c.unlock(Zeroizing::new("wrong passphrase!!".into())).await.is_err());
    c.unlock(pass()).await.unwrap();
    // Same keys after unlock: the pairing code identifies the same device.
    let code2 = c.my_code().unwrap();
    let (p1, p2) = (pairing::decode(&code1.code).unwrap(), pairing::decode(&code2.code).unwrap());
    assert_eq!(p1.identity_key, p2.identity_key);
    assert_eq!(p1.onion, p2.onion);
    assert_eq!(p1.noise_static, p2.noise_static);
    assert!(c.verify_passphrase(pass()).await.unwrap());
}

#[tokio::test]
async fn pairing_and_verification_gate() {
    let (da, db_) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (core(da.path()), core(db_.path()));
    a.create_vault("Alice", pass()).await.unwrap();
    b.create_vault("Bob", pass()).await.unwrap();
    let id = a.add_contact(&b.my_code().unwrap().code, None).await.unwrap();
    assert!(matches!(a.add_contact(&b.my_code().unwrap().code, None).await, Err(CoreError::AlreadyPaired)));
    assert!(matches!(a.add_contact(&a.my_code().unwrap().code, None).await, Err(CoreError::OwnCode)));
    let contacts = a.contacts().await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "Bob");
    assert!(!contacts[0].verified);
    // Sending is blocked until verified.
    assert!(matches!(a.send_text(id, "hi").await, Err(CoreError::NotVerified)));
    // Both sides compute the same safety number.
    let bid = b.add_contact(&a.my_code().unwrap().code, None).await.unwrap();
    assert_eq!(a.safety_number(id).unwrap(), b.safety_number(bid).unwrap());
    assert_eq!(a.safety_number(id).unwrap().len(), 12);
    // Verification needs the friend's digits: wrong digits (as under a MITM) are refused.
    let theirs = b.safety_number(bid).unwrap();
    assert!(matches!(a.verify_contact(id, &[(0, "00000".into()), (5, theirs[5].clone())]), Err(CoreError::SafetyMismatch)));
    assert!(matches!(a.verify_contact(id, &[(5, theirs[5].clone())]), Err(CoreError::Invalid(_))));
    assert!(matches!(a.verify_contact(id, &[(5, theirs[5].clone()), (5, theirs[5].clone())]), Err(CoreError::Invalid(_))));
    assert!(matches!(a.send_text(id, "hi").await, Err(CoreError::NotVerified)));
    a.verify_contact(id, &[(3, theirs[3].clone()), (11, format!(" {} ", theirs[11]))]).unwrap();
    let m = a.send_text(id, "hello").await.unwrap();
    assert_eq!(m.status, "queued");
    assert_eq!(a.contacts().await.unwrap()[0].queued, 1);
    assert!(matches!(a.send_text(id, "   ").await, Err(CoreError::BadMessage)));
    assert!(matches!(a.send_text(id, &"x".repeat(MAX_TEXT_BYTES + 1)).await, Err(CoreError::BadMessage)));
    // Deleting the contact removes messages and outbox.
    a.delete_contact(id).await.unwrap();
    assert!(a.contacts().await.unwrap().is_empty());
    assert!(a.messages(id, 50, None).unwrap().is_empty());
}

#[tokio::test]
async fn panic_wipe_destroys_vault() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(dir.path());
    c.create_vault("X", pass()).await.unwrap();
    c.panic_wipe().await.unwrap();
    assert_eq!(c.state(), AppState::NoVault);
    assert!(!dir.path().join("vault").join("vault.db").exists());
}

#[tokio::test]
async fn settings_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(dir.path());
    c.create_vault("X", pass()).await.unwrap();
    assert_eq!(c.settings().unwrap(), Settings::default());
    let s = Settings { read_receipts: true, auto_lock_minutes: 5, notifications: true, bridges: vec![] };
    c.set_settings(s.clone()).await.unwrap();
    assert_eq!(c.settings().unwrap(), s);
}

#[test]
fn timer_texts() {
    assert_eq!(timer_text(0, true), "You turned off disappearing messages.");
    assert_eq!(timer_text(86400, false), "Your contact set disappearing messages to 1 day.");
    assert_eq!(timer_text(3 * 3600, true), "You set disappearing messages to 3 hours.");
}

#[test]
fn file_names_are_sanitized() {
    assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
    assert_eq!(sanitize_file_name("C:\\Users\\x\\photo.jpg"), "photo.jpg");
    assert_eq!(sanitize_file_name("invoice\u{202e}fdp.exe"), "invoicefdp.exe");
    assert_eq!(sanitize_file_name("a<b>c:d|e?f*g\"\n.txt"), "abcdefg.txt");
    assert_eq!(sanitize_file_name(".hidden"), "hidden");
    assert_eq!(sanitize_file_name("trailing. . "), "trailing");
    assert_eq!(sanitize_file_name("   "), "file");
    assert_eq!(sanitize_file_name(&"x".repeat(500)).len(), 120);
}

/// Two paired, verified cores without networking.
async fn paired() -> (tempfile::TempDir, tempfile::TempDir, Core, Core, i64, i64) {
    let (da, db_) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (core(da.path()), core(db_.path()));
    a.create_vault("Alice", pass()).await.unwrap();
    b.create_vault("Bob", pass()).await.unwrap();
    let a_bob = a.add_contact(&b.my_code().unwrap().code, None).await.unwrap();
    let b_alice = b.add_contact(&a.my_code().unwrap().code, None).await.unwrap();
    a.verify_contact_for_tests(a_bob).unwrap();
    b.verify_contact_for_tests(b_alice).unwrap();
    (da, db_, a, b, a_bob, b_alice)
}

/// Moves everything in `from`'s outbox to `to` as if delivered (no crypto), acking each item.
/// `tamper` may modify the content of each item before delivery.
fn deliver(from: &Core, from_contact: i64, to: &Core, to_contact: i64, mut tamper: impl FnMut(&mut Content)) {
    let items = from.inner.with(|u| Ok(db::outbox_for(u.vault.conn(), from_contact, 100_000)?)).unwrap();
    for item in items {
        let mut content = Content::decode(&item.content[..]).unwrap();
        tamper(&mut content);
        to.inner.with(|u| peer::apply_content(u.vault.conn(), to_contact, content)).unwrap();
        from.inner.with(|u| Ok(db::outbox_ack(u.vault.conn(), from_contact, &item.id)?)).unwrap();
    }
}

fn last_message(c: &Core, contact: i64) -> MessageView {
    c.messages(contact, 500, None).unwrap().pop().unwrap()
}

#[tokio::test]
async fn disappearing_defaults_to_a_week_counted_from_delivery() {
    let (_da, _db, a, b, a_bob, b_alice) = paired().await;
    assert_eq!(a.contacts().await.unwrap()[0].disappear_secs, db::DEFAULT_DISAPPEAR_SECS);
    let sent = a.send_text(a_bob, "hi").await.unwrap();
    // Not delivered yet: the countdown hasn't started, however long it waits.
    assert_eq!(sent.expires_at, None);
    let before = db::now_ms();
    deliver(&a, a_bob, &b, b_alice, |_| {});
    let week = i64::from(db::DEFAULT_DISAPPEAR_SECS) * 1000;
    let received = last_message(&b, b_alice);
    assert!(received.expires_at.unwrap() >= before + week, "receiver counts from receipt");
    let delivered = last_message(&a, a_bob);
    assert_eq!(delivered.status, "delivered");
    assert!(delivered.expires_at.unwrap() >= before + week, "sender counts from delivery");
}

#[tokio::test]
async fn file_transfer_roundtrip() {
    let (_da, _db, a, b, a_bob, b_alice) = paired().await;
    // Validation.
    assert!(matches!(a.send_file(a_bob, "x", Zeroizing::new(vec![])).await, Err(CoreError::BadFile)));
    let too_big = vec![0u8; MAX_FILE_BYTES as usize + 1];
    assert!(matches!(a.send_file(a_bob, "x", Zeroizing::new(too_big)).await, Err(CoreError::BadFile)));

    // 3.5 chunks of pseudo-random data.
    let data: Vec<u8> = (0..FILE_CHUNK_BYTES * 7 / 2).map(|i| (i * 31 % 251) as u8).collect();
    let sent = a.send_file(a_bob, "../holiday photo.jpg", Zeroizing::new(data.clone())).await.unwrap();
    let f = sent.file.clone().unwrap();
    assert_eq!((sent.kind, f.name.as_str(), f.state, f.total, f.size), ("file", "holiday photo.jpg", "sending", 4, data.len() as i64));
    // A text sent afterwards jumps ahead of the file data in the outbox.
    a.send_text(a_bob, "after the file").await.unwrap();
    let order: Vec<Content> = a
        .inner
        .with(|u| Ok(db::outbox_for(u.vault.conn(), a_bob, 100)?))
        .unwrap()
        .iter()
        .map(|i| Content::decode(&i.content[..]).unwrap())
        .collect();
    assert!(matches!(order[0].body, Some(content::Body::FileHeader(_))));
    assert!(matches!(order[1].body, Some(content::Body::Text(_))));
    assert!(order[2..].iter().all(|c| matches!(c.body, Some(content::Body::FileChunk(_)))));
    assert_eq!(a.contacts().await.unwrap()[0].queued, 6);

    deliver(&a, a_bob, &b, b_alice, |_| {});
    let got = b.messages(b_alice, 500, None).unwrap();
    let file_msg = got.iter().find(|m| m.kind == "file").unwrap();
    let rf = file_msg.file.clone().unwrap();
    assert_eq!((rf.state, rf.done, rf.total, rf.name.as_str()), ("received", 4, 4, "holiday photo.jpg"));
    assert!(file_msg.expires_at.is_some());
    let (name, bytes) = b.file_data(&file_msg.id).unwrap();
    assert_eq!(name, "holiday photo.jpg");
    assert_eq!(&bytes[..], &data[..]);

    let mine = a.messages(a_bob, 500, None).unwrap().into_iter().find(|m| m.kind == "file").unwrap();
    assert_eq!((mine.status, mine.file.as_ref().unwrap().state), ("delivered", "sent"));
    assert!(mine.expires_at.is_some(), "sent file starts its countdown on delivery");
    assert!(a.file_data(&mine.id).is_err(), "the sender keeps no copy");
    assert_eq!(a.contacts().await.unwrap()[0].queued, 0);

    // Disappearing removes the stored file data too.
    b.inner
        .with(|u| {
            let c = u.vault.conn();
            c.execute("UPDATE messages SET expires_at = 1 WHERE kind = ?1", [db::KIND_FILE])?;
            db::expire(c)?;
            let left: i64 = c.query_row("SELECT count(*) FROM attachment_chunks", [], |r| r.get(0))?;
            assert_eq!(left, 0);
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn corrupted_or_unverified_files_are_rejected() {
    let (_da, _db, a, b, a_bob, b_alice) = paired().await;
    let data = vec![7u8; FILE_CHUNK_BYTES + 10];

    // A chunk altered in transit (hash no longer matches) → failed, data discarded.
    a.send_file(a_bob, "a.bin", Zeroizing::new(data.clone())).await.unwrap();
    deliver(&a, a_bob, &b, b_alice, |c| {
        if let Some(content::Body::FileChunk(ch)) = &mut c.body
            && ch.index == 0
        {
            ch.data[0] ^= 1;
        }
    });
    let m = last_message(&b, b_alice);
    assert_eq!(m.file.as_ref().unwrap().state, "failed");
    assert!(b.file_data(&m.id).is_err());

    // A chunk of the wrong size → failed immediately.
    a.send_file(a_bob, "b.bin", Zeroizing::new(data.clone())).await.unwrap();
    deliver(&a, a_bob, &b, b_alice, |c| {
        if let Some(content::Body::FileChunk(ch)) = &mut c.body {
            ch.data.push(0);
        }
    });
    assert_eq!(last_message(&b, b_alice).file.unwrap().state, "failed");

    // A header that lies about the chunk count → ignored.
    let before = b.messages(b_alice, 500, None).unwrap().len();
    a.send_file(a_bob, "c.bin", Zeroizing::new(data.clone())).await.unwrap();
    deliver(&a, a_bob, &b, b_alice, |c| {
        if let Some(content::Body::FileHeader(h)) = &mut c.body {
            h.chunk_count += 1;
        }
    });
    assert_eq!(b.messages(b_alice, 500, None).unwrap().len(), before);

    // From a contact Bob hasn't verified → ignored.
    b.unverify_contact(b_alice).unwrap();
    a.send_file(a_bob, "d.bin", Zeroizing::new(data)).await.unwrap();
    deliver(&a, a_bob, &b, b_alice, |_| {});
    assert_eq!(b.messages(b_alice, 500, None).unwrap().len(), before);
}

#[test]
fn largest_chunk_fits_in_a_frame() {
    // Worst case: a full chunk in a PreKey envelope (Kyber ciphertext etc.), padded.
    let content = Content {
        id: vec![0; 16],
        sent_at_ms: u64::MAX,
        expire_secs: u32::MAX,
        body: Some(content::Body::FileChunk(p2p_proto::FileChunk {
            file_id: vec![0; 16],
            index: u32::MAX,
            data: vec![0xff; FILE_CHUNK_BYTES],
        })),
    };
    let padded = p2p_signal::pad(&content.encode_to_vec()).len();
    let prekey_overhead = 4096;
    let envelope = 16 + 16 + padded + prekey_overhead;
    assert!(envelope < *p2p_proto::FRAME_BUCKETS.last().unwrap(), "{envelope}");
}
