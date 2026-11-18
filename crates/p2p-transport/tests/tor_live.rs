//! Live tests against the real Tor network. Run with:
//! `cargo test -p p2p-transport --test tor_live -- --ignored --nocapture`

use std::time::Duration;

use p2p_transport::onion::ClientAuthKey;
use p2p_transport::tor::{Tor, TorConfig, find_tor_binary};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn launch(dir: &std::path::Path, name: &str) -> Tor {
    let cfg = TorConfig {
        tor_binary: find_tor_binary(None).expect("tor binary"),
        data_dir: dir.join(name),
        bridges: vec![],
        pt_binary: None,
    };
    let tor = Tor::launch(&cfg).await.expect("launch");
    tor.wait_bootstrapped(Duration::from_secs(180), |p| eprintln!("[{name}] bootstrap {p}%"))
        .await
        .expect("bootstrap");
    tor
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn onion_service_with_client_auth() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();
    let dir = tempfile::tempdir().unwrap();
    let (host, client, stranger) =
        tokio::join!(launch(dir.path(), "host"), launch(dir.path(), "client"), launch(dir.path(), "stranger"));

    // Host: local listener that echoes one message.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 5];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                }
            });
        }
    });

    let auth = ClientAuthKey::generate();
    // Key generated locally (not by Tor): Tor must accept it and derive the same address.
    let (blob, local_id) = p2p_transport::onion::generate_onion_identity();
    let key = p2p_transport::tor::OnionKey::from_blob(blob.to_string());
    let id = host.publish_onion(&key, 7001, target, &[auth.public_bytes()]).await.unwrap().unwrap();
    assert_eq!(id, local_id, "Tor derives the same onion address as our local key generation");
    // Republishing requires removing the old service first.
    host.unpublish_onion(&id).await.unwrap();
    let id2 = host.publish_onion(&key, 7001, target, &[auth.public_bytes()]).await.unwrap().unwrap();
    assert_eq!(id2, id);
    eprintln!("published {}", id.hostname());

    client.add_client_auth(&id, &auth.secret_bytes()).await.unwrap();

    // Authorized client: retry while the descriptor propagates.
    let mut ok = false;
    for attempt in 1..=12 {
        match tokio_socks::tcp::Socks5Stream::connect(client.socks_addr(), (id.hostname().as_str(), 7001)).await {
            Ok(mut s) => {
                s.write_all(b"hello").await.unwrap();
                let mut buf = [0u8; 5];
                s.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello");
                ok = true;
                eprintln!("authorized client connected on attempt {attempt}");
                break;
            }
            Err(e) => {
                eprintln!("attempt {attempt}: {e}");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
    assert!(ok, "authorized client could not connect");

    // Stranger without the client-auth key must fail.
    let r = tokio::time::timeout(
        Duration::from_secs(90),
        tokio_socks::tcp::Socks5Stream::connect(stranger.socks_addr(), (id.hostname().as_str(), 7001)),
    )
    .await;
    assert!(!matches!(r, Ok(Ok(_))), "stranger connected without client auth!");
    eprintln!("stranger correctly refused: {r:?}");

    host.shutdown().await;
    client.shutdown().await;
    stranger.shutdown().await;
}
