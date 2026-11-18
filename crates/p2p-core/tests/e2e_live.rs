//! Full end-to-end test: two app cores, each with its own Tor, talking over real onion
//! services. Run with:
//! `cargo test -p p2p-core --test e2e_live -- --ignored --nocapture`

use std::time::Duration;

use p2p_core::{Config, Core, Event, Settings};
use p2p_vault::KdfParams;
use tokio::sync::broadcast::Receiver;
use zeroize::Zeroizing;

fn pass() -> Zeroizing<String> {
    Zeroizing::new("correct horse battery staple".to_string())
}

fn core(dir: &std::path::Path) -> Core {
    Core::new(Config { data_dir: dir.to_path_buf(), tor_binary: None, pt_binary: None, kdf: KdfParams::INSECURE_TEST_ONLY })
}

async fn wait_for(rx: &mut Receiver<Event>, what: &str, timeout: Duration, mut pred: impl FnMut(&Event) -> bool) -> Event {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Ok(e)) => {
                if let Event::Tor { progress, error: Some(err), .. } = &e {
                    panic!("tor error while waiting for {what}: {err} ({progress}%)");
                }
                if let Event::Tor { progress, .. } = &e
                    && progress % 25 == 0
                {
                    eprintln!("[{what}] tor {progress}%");
                }
                if pred(&e) {
                    return e;
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(e)) => panic!("event channel closed: {e}"),
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

fn is_tor_ready(e: &Event) -> bool {
    matches!(e, Event::Tor { ready: true, .. })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn two_apps_chat_over_tor() {
    let _ = tracing_subscriber::fmt().with_env_filter("p2p_core=debug,warn").try_init();
    let (da, db_) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, bob) = (core(da.path()), core(db_.path()));
    let (mut ea, mut eb) = (alice.subscribe(), bob.subscribe());

    alice.create_vault("Alice", pass()).await.unwrap();
    bob.create_vault("Bob", pass()).await.unwrap();
    let t = Duration::from_secs(300);
    tokio::join!(wait_for(&mut ea, "alice tor", t, is_tor_ready), wait_for(&mut eb, "bob tor", t, is_tor_ready));
    eprintln!("both Tor instances ready");

    // Pair (codes would travel by email) and verify (safety number compared on a call).
    let a_bob = alice.add_contact(&bob.my_code().unwrap().code, None).await.unwrap();
    let b_alice = bob.add_contact(&alice.my_code().unwrap().code, None).await.unwrap();
    assert_eq!(alice.safety_number(a_bob).unwrap(), bob.safety_number(b_alice).unwrap());
    alice.verify_contact_for_tests(a_bob).unwrap();
    bob.verify_contact_for_tests(b_alice).unwrap();
    bob.set_settings(Settings { read_receipts: true, ..Settings::default() }).await.unwrap();

    // Alice → Bob (queued until the onion services are reachable).
    let sent = alice.send_text(a_bob, "hello bob, this is alice").await.unwrap();
    let got = wait_for(&mut eb, "bob receives", Duration::from_secs(400), |e| {
        matches!(e, Event::Message { message } if !message.outgoing && message.body == "hello bob, this is alice")
    })
    .await;
    eprintln!("bob received: {got:?}");
    wait_for(&mut ea, "alice delivered", Duration::from_secs(120), |e| {
        matches!(e, Event::Message { message } if message.id == sent.id && message.status == "delivered")
    })
    .await;
    eprintln!("alice sees delivered");
    // New contacts default to a 1-week timer that starts on delivery / receipt.
    let week = 7 * 24 * 3600 * 1000;
    let mine = alice.messages(a_bob, 500, None).unwrap().into_iter().find(|m| m.id == sent.id).unwrap();
    assert!(mine.expires_at.unwrap() > sent.ts + week, "sender's countdown starts at delivery");
    if let Event::Message { message } = &got {
        assert!(message.expires_at.unwrap() >= message.ts + week);
    }

    // Bob reads → read receipt to Alice.
    bob.mark_read(b_alice).await.unwrap();
    wait_for(&mut ea, "alice read receipt", Duration::from_secs(120), |e| {
        matches!(e, Event::Message { message } if message.id == sent.id && message.status == "read")
    })
    .await;
    eprintln!("alice sees read");

    // Bob → Alice.
    bob.send_text(b_alice, "hi alice! got it").await.unwrap();
    wait_for(&mut ea, "alice receives", Duration::from_secs(120), |e| {
        matches!(e, Event::Message { message } if !message.outgoing && message.body == "hi alice! got it")
    })
    .await;
    eprintln!("alice received reply");

    // Disappearing messages: Alice sets 10 s; Bob's side updates and the next message expires.
    alice.set_disappearing(a_bob, 10).await.unwrap();
    wait_for(&mut eb, "bob timer update", Duration::from_secs(120), |e| {
        matches!(e, Event::Message { message } if message.kind == "system")
    })
    .await;
    assert_eq!(bob.contacts().await.unwrap()[0].disappear_secs, 10);
    alice.send_text(a_bob, "this will vanish").await.unwrap();
    let vanish = wait_for(&mut eb, "bob receives vanishing", Duration::from_secs(120), |e| {
        matches!(e, Event::Message { message } if message.body == "this will vanish")
    })
    .await;
    let Event::Message { message: vanish } = vanish else { unreachable!() };
    assert!(vanish.expires_at.is_some());
    wait_for(&mut eb, "bob deletes vanishing", Duration::from_secs(60), |e| {
        matches!(e, Event::Deleted { ids, .. } if ids.contains(&vanish.id))
    })
    .await;
    eprintln!("disappearing message deleted on bob's side");
    alice.set_disappearing(a_bob, 0).await.unwrap();

    // Offline delivery: Bob locks (Tor stops); Alice sends; Bob unlocks later and receives.
    tokio::time::sleep(Duration::from_secs(3)).await;
    bob.lock().await;
    let queued = alice.send_text(a_bob, "sent while you were offline").await.unwrap();
    // Regression test for PR #1: a backlog larger than the old per-second limit (50) and the
    // outbox batch (100) must be delivered completely, without a "too fast" security alarm.
    const BACKLOG: usize = 120;
    for i in 0..BACKLOG {
        alice.send_text(a_bob, &format!("backlog {i}")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(alice.messages(a_bob, 500, None).unwrap().iter().find(|m| m.id == queued.id).unwrap().status, "queued");
    let mut eb = bob.subscribe();
    bob.unlock(pass()).await.unwrap();
    wait_for(&mut eb, "bob receives offline msg", Duration::from_secs(600), |e| {
        matches!(e, Event::Message { message } if message.body == "sent while you were offline")
    })
    .await;
    eprintln!("offline message delivered after unlock");
    let mut got = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    while got < BACKLOG {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, eb.recv()).await {
            Ok(Ok(Event::Message { message })) if !message.outgoing && message.body.starts_with("backlog ") => got += 1,
            Ok(Ok(Event::Security { message, .. })) => panic!("security alarm during backlog delivery: {message}"),
            Ok(Ok(_)) | Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(e)) => panic!("event channel closed: {e}"),
            Err(_) => panic!("only {got}/{BACKLOG} backlog messages arrived"),
        }
    }
    let history = bob.messages(b_alice, 500, None).unwrap();
    assert_eq!(history.iter().filter(|m| m.body.starts_with("backlog ")).count(), BACKLOG, "no duplicates, none missing");
    eprintln!("backlog of {BACKLOG} delivered completely, no alarm");

    // File transfer over Tor: ~2 MB (43 chunks), verified byte for byte. A text sent just after
    // it must overtake the file data: only BULK_IN_FLIGHT chunks may be queued ahead of it.
    let data: Vec<u8> = (0..2_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let file = alice.send_file(a_bob, "report.pdf", Zeroizing::new(data.clone())).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let sent_at = std::time::Instant::now();
    alice.send_text(a_bob, "sent during the transfer").await.unwrap();
    let mut text_after = None;
    let received = wait_for(&mut eb, "bob receives file", Duration::from_secs(400), |e| {
        if let Event::Message { message } = e {
            if message.body == "sent during the transfer" && text_after.is_none() {
                text_after = Some(sent_at.elapsed());
            }
            return message.file.as_ref().is_some_and(|f| f.state == "received");
        }
        false
    })
    .await;
    let text_after = text_after.expect("the text must arrive before the file finishes");
    eprintln!("text sent during the file transfer arrived after {text_after:?}");
    let Event::Message { message } = received else { unreachable!() };
    let (name, bytes) = bob.file_data(&message.id).unwrap();
    assert_eq!((name.as_str(), &bytes[..]), ("report.pdf", &data[..]));
    wait_for(&mut ea, "alice file sent", Duration::from_secs(120), |e| {
        matches!(e, Event::Message { message } if message.id == file.id && message.status == "delivered")
    })
    .await;
    eprintln!("file of {} bytes delivered and verified", data.len());

    // History persisted across lock/unlock, encrypted at rest.
    let history = bob.messages(b_alice, 500, None).unwrap();
    assert!(history.iter().any(|m| m.body == "hello bob, this is alice"));
    assert!(!history.iter().any(|m| m.body == "this will vanish"));

    alice.lock().await;
    bob.lock().await;
}
