//! The protocol spoken on one authenticated connection with a contact.
//!
//! 1. Both sides send `Hello { has_session }`.
//! 2. Session setup is driven by a fixed **initiator** (the side with the smaller identity key):
//!    if either side lacks a session, the initiator sends `BundleRequest`, the responder answers
//!    with a fresh `Bundle`, the initiator runs PQXDH and sends an encrypted `SessionInit`.
//! 3. Messages flow as Signal `Envelope`s; each is acknowledged with `Ack` only after it has
//!    been stored, and the sender then removes it from its outbox. Unacknowledged messages are
//!    re-encrypted and re-sent on the next connection; receivers de-duplicate by content ID.
//! 4. `Ping`/`Pong` keep the circuit alive; 90 s of silence closes the connection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2p_proto::{
    Ack, Bundle, BundleRequest, Content, Envelope, FILE_CHUNK_BYTES, Frame, Hello, MAX_FILE_BYTES, PROTOCOL_VERSION, Ping,
    ProstMessage, content, decode_frame, encode_frame, frame::Body,
};
use p2p_transport::noise::{FrameReader, SecureChannel};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::net::{ConnHandle, Network, jitter};
use crate::{CoreError, Event, Inner, MAX_DISAPPEAR_SECS, MAX_TEXT_BYTES, db, sanitize_file_name, timer_text};

const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const PING_EVERY: Duration = Duration::from_secs(30);
const MAX_HANDSHAKES_PER_CONN: u8 = 3;
const MAX_BUNDLES_PER_CONN: u8 = 3;
// Must stay comfortably above OUTBOX_BATCH: a peer coming online legitimately flushes a whole
// batch of queued messages at once, and on a fast link (e.g. loopback) they all arrive within
// one second. A lower cap would drop that connection with a false "too fast" security alarm.
const MAX_ENVELOPES_PER_SEC: u32 = 256;
const OUTBOX_BATCH: u32 = 100;
/// File chunks (~64 KB on the wire each) allowed in flight at once. A text sent during a
/// transfer only waits behind these, not behind a whole batch: about 6 s at Tor's ~60 KB/s
/// instead of the 27 s measured on Windows with 100. Still enough to keep a slow onion
/// circuit busy (6 × 48 KB per round trip).
const BULK_IN_FLIGHT: usize = 6;
// Compile-time guard for the bug fixed in PR #1: a full outbox batch must never trip the limit.
const _: () = assert!(MAX_ENVELOPES_PER_SEC >= 2 * OUTBOX_BATCH);
/// Files a contact may have in transfer to us at once (bounds the disk they can fill).
const MAX_INCOMING_FILES: i64 = 8;

pub(crate) enum Cmd {
    /// New outbox items: try to send.
    Kick,
    /// Close this connection.
    Close,
}

struct Peer {
    inner: Arc<Inner>,
    contact_id: i64,
    peer_identity: Vec<u8>,
    /// Fixed session-setup role (smaller identity key initiates).
    initiator: bool,
    peer_has_session: Option<bool>,
    bundle_pending: bool,
    handshakes: u8,
    bundles_served: u8,
    /// Sent but not yet acknowledged: id → is file data.
    in_flight: HashMap<Vec<u8>, bool>,
    out: mpsc::Sender<Vec<u8>>,
    window_start: Instant,
    window_count: u32,
}

/// Why the connection must close.
enum Close {
    Normal,
    Security(String),
}

pub(crate) async fn run<S>(inner: Arc<Inner>, net: Arc<Network>, contact_id: i64, chan: SecureChannel<S>, dialer_key: [u8; 32])
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let Ok((my_identity, peer_identity)) = inner.with(|u| {
        let c = db::contact(u.vault.conn(), contact_id)?.ok_or(CoreError::NoContact)?;
        Ok((u.identity.public_bytes(), c.identity_key))
    }) else {
        return;
    };

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(32);
    let conn_id = net.next_conn_id();
    if !net.register(&inner, contact_id, ConnHandle { conn_id, initiator: dialer_key, cmd: cmd_tx }) {
        return;
    }

    let (mut reader, mut writer) = chan.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(128);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if writer.write_frame(&frame).await.is_err() {
                break;
            }
        }
        writer.shutdown().await;
    });

    let mut peer = Peer {
        inner: inner.clone(),
        contact_id,
        initiator: my_identity < peer_identity,
        peer_identity,
        peer_has_session: None,
        bundle_pending: false,
        handshakes: 0,
        bundles_served: 0,
        in_flight: HashMap::new(),
        out: out_tx,
        window_start: Instant::now(),
        window_count: 0,
    };

    let result = peer.drive(&mut reader, &mut cmd_rx).await;
    if let Close::Security(msg) = result {
        tracing::warn!("closing connection to contact {contact_id}: {msg}");
        inner.emit(Event::Security { contact_id, message: msg });
    }
    drop(peer);
    let _ = writer_task.await;
    net.unregister(&inner, contact_id, conn_id);
}

impl Peer {
    async fn drive<S: AsyncRead>(&mut self, reader: &mut FrameReader<S>, cmds: &mut mpsc::Receiver<Cmd>) -> Close {
        let has = self.has_session();
        if self.send(Body::Hello(Hello { protocol_version: PROTOCOL_VERSION, has_session: has })).await.is_err() {
            return Close::Normal;
        }
        let mut next_ping = tokio::time::Instant::now() + PING_EVERY + jitter(Duration::from_secs(10));
        loop {
            tokio::select! {
                frame = tokio::time::timeout(IDLE_TIMEOUT, reader.read_frame()) => {
                    let Ok(Ok(bytes)) = frame else { return Close::Normal };
                    let Ok(frame) = decode_frame(&bytes) else {
                        return Close::Security("received a malformed frame".into());
                    };
                    match self.handle(frame).await {
                        Ok(()) => {}
                        Err(c) => return c,
                    }
                }
                cmd = cmds.recv() => match cmd {
                    Some(Cmd::Kick) => { if self.flush().await.is_err() { return Close::Normal; } }
                    Some(Cmd::Close) | None => return Close::Normal,
                },
                _ = tokio::time::sleep_until(next_ping) => {
                    let nonce = u64::from_le_bytes(db::random_id()[..8].try_into().expect("8 bytes"));
                    if self.send(Body::Ping(Ping { nonce })).await.is_err() { return Close::Normal; }
                    next_ping = tokio::time::Instant::now() + PING_EVERY + jitter(Duration::from_secs(10));
                }
            }
        }
    }

    async fn send(&self, body: Body) -> Result<(), ()> {
        self.out.send(encode_frame(Frame { body: Some(body), padding: vec![] })).await.map_err(|_| ())
    }

    fn has_session(&self) -> bool {
        self.inner
            .with(|u| Ok(p2p_signal::has_session(u.vault.conn(), &u.identity, &self.peer_identity)?))
            .unwrap_or(false)
    }

    async fn handle(&mut self, frame: Frame) -> Result<(), Close> {
        let closed = |_| Close::Normal;
        match frame.body {
            Some(Body::Hello(h)) => {
                if h.protocol_version != PROTOCOL_VERSION {
                    return Err(Close::Security("your contact runs an incompatible app version".into()));
                }
                self.peer_has_session = Some(h.has_session);
                self.maybe_establish(false).await.map_err(closed)?;
                self.flush().await.map_err(closed)?;
            }
            Some(Body::BundleRequest(_)) => {
                if self.initiator || self.bundles_served >= MAX_BUNDLES_PER_CONN {
                    return Ok(());
                }
                self.bundles_served += 1;
                let bundle = self.inner.with(|u| Ok(p2p_signal::new_bundle(u.vault.conn(), &u.identity)?));
                if let Ok(b) = bundle {
                    self.send(Body::Bundle(b)).await.map_err(closed)?;
                }
            }
            Some(Body::Bundle(b)) => self.on_bundle(b).await?,
            Some(Body::Envelope(e)) => {
                self.rate_limit()?;
                self.on_envelope(e).await?;
            }
            Some(Body::Ack(a)) => {
                let was_bulk = self.on_ack(a);
                // A whole batch was acknowledged: send the next one. Without this, outboxes
                // larger than OUTBOX_BATCH stalled until some unrelated event triggered a flush.
                // A file chunk was acknowledged: refill the file window.
                if self.in_flight.is_empty() || was_bulk {
                    self.flush().await.map_err(closed)?;
                }
            }
            Some(Body::Ping(p)) => self.send(Body::Pong(p)).await.map_err(closed)?,
            Some(Body::Pong(_)) | None => {}
        }
        Ok(())
    }

    fn rate_limit(&mut self) -> Result<(), Close> {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.window_start = Instant::now();
            self.window_count = 0;
        }
        self.window_count += 1;
        if self.window_count > MAX_ENVELOPES_PER_SEC {
            return Err(Close::Security("contact sent messages too fast".into()));
        }
        Ok(())
    }

    /// Initiator only: request a bundle if either side lacks a usable session (or `force`).
    async fn maybe_establish(&mut self, force: bool) -> Result<(), ()> {
        if !self.initiator || self.bundle_pending || self.handshakes >= MAX_HANDSHAKES_PER_CONN {
            return Ok(());
        }
        let needed = force || !self.has_session() || self.peer_has_session == Some(false);
        if needed {
            self.handshakes += 1;
            self.bundle_pending = true;
            self.send(Body::BundleRequest(BundleRequest {})).await?;
        }
        Ok(())
    }

    async fn on_bundle(&mut self, bundle: Bundle) -> Result<(), Close> {
        if !self.initiator || !self.bundle_pending {
            return Ok(());
        }
        self.bundle_pending = false;
        let r = self.inner.with(|u| Ok(p2p_signal::start_session(u.vault.conn(), &u.identity, &self.peer_identity, &bundle)?));
        match r {
            Ok(()) => {}
            Err(CoreError::Signal(p2p_signal::Error::UntrustedIdentity)) => {
                return Err(Close::Security(
                    "this contact presented a different identity key than the one you paired with. \
                     Messages are blocked. Re-pair and verify the safety number on a call."
                        .into(),
                ));
            }
            Err(e) => {
                tracing::warn!("session setup failed: {e}");
                return Ok(());
            }
        }
        // New session: everything unacknowledged must be re-sent under it.
        self.in_flight.clear();
        self.peer_has_session = Some(true);
        self.send_control(content::Body::SessionInit(p2p_proto::SessionInit {})).await.map_err(|_| Close::Normal)?;
        self.flush().await.map_err(|_| Close::Normal)
    }

    /// Sends a one-off encrypted control message (not stored in the outbox).
    async fn send_control(&mut self, body: content::Body) -> Result<(), ()> {
        let id = db::random_id();
        let content = Content { id: id.clone(), sent_at_ms: db::now_ms() as u64, expire_secs: 0, body: Some(body) };
        let env = self.inner.with(|u| {
            let pt = p2p_signal::pad(&content.encode_to_vec());
            Ok(p2p_signal::encrypt(u.vault.conn(), &u.identity, &self.peer_identity, &pt)?)
        });
        match env {
            Ok((kind, ciphertext)) => self.send(Body::Envelope(Envelope { kind, ciphertext, id })).await,
            Err(_) => Ok(()),
        }
    }

    async fn on_envelope(&mut self, env: Envelope) -> Result<(), Close> {
        let contact_id = self.contact_id;
        let peer_identity = self.peer_identity.clone();
        let result = self.inner.with(|u| {
            let c = u.vault.conn();
            let tx = c.unchecked_transaction()?;
            let pt = p2p_signal::decrypt(c, &u.identity, &peer_identity, env.kind, &env.ciphertext)?;
            let raw = p2p_signal::unpad(&pt)?;
            let content = Content::decode(raw).map_err(|_| CoreError::Invalid("content"))?;
            let events = apply_content(c, contact_id, content)?;
            tx.commit()?;
            Ok(events)
        });
        match result {
            Ok(Applied { events, reply_init }) => {
                for e in events {
                    self.inner.emit(e);
                }
                self.send(Body::Ack(Ack { id: env.id })).await.map_err(|_| Close::Normal)?;
                // A message decrypted, so we hold a working session and so does the peer.
                self.peer_has_session = Some(true);
                if reply_init && !self.initiator {
                    // Acknowledge the new session so the initiator stops sending PreKey messages.
                    self.send_control(content::Body::SessionInit(p2p_proto::SessionInit {})).await.map_err(|_| Close::Normal)?;
                }
                self.flush().await.map_err(|_| Close::Normal)
            }
            Err(CoreError::Signal(p2p_signal::Error::UntrustedIdentity)) => Err(Close::Security(
                "a message was signed by an identity key you never verified. It was blocked.".into(),
            )),
            Err(e) => {
                tracing::warn!("could not decrypt message from contact {contact_id}: {e}");
                // Sessions are out of sync: rebuild them (bounded per connection).
                if self.initiator {
                    self.maybe_establish(true).await.map_err(|_| Close::Normal)?;
                } else if self.handshakes < MAX_HANDSHAKES_PER_CONN {
                    self.handshakes += 1;
                    self.send(Body::Hello(Hello { protocol_version: PROTOCOL_VERSION, has_session: false }))
                        .await
                        .map_err(|_| Close::Normal)?;
                }
                Ok(())
            }
        }
    }

    /// Returns whether the acknowledged item was file data.
    fn on_ack(&mut self, ack: Ack) -> bool {
        let Some(bulk) = self.in_flight.remove(&ack.id) else {
            return false;
        };
        let contact_id = self.contact_id;
        if let Ok(Some(view)) = self.inner.with(|u| {
            let c = u.vault.conn();
            let msg = db::outbox_ack(c, contact_id, &ack.id)?;
            Ok(match msg {
                Some(m) => db::message(c, &m)?,
                None => None,
            })
        }) {
            self.inner.emit(Event::Message { message: view });
            self.inner.emit(Event::Contacts);
        }
        bulk
    }

    /// Encrypts and sends the outbox items not already in flight on this connection (file
    /// data only up to BULK_IN_FLIGHT at a time).
    async fn flush(&mut self) -> Result<(), ()> {
        if self.peer_has_session == Some(false) || !self.has_session() {
            return Ok(());
        }
        let skip = self.in_flight.clone();
        let peer_identity = self.peer_identity.clone();
        let contact_id = self.contact_id;
        let envelopes = self.inner.with(|u| {
            let c = u.vault.conn();
            let mut out = Vec::new();
            let items = db::outbox_for(c, contact_id, OUTBOX_BATCH)?;
            for item in to_send(&items, &skip) {
                let pt = p2p_signal::pad(&item.content);
                let (kind, ciphertext) = p2p_signal::encrypt(c, &u.identity, &peer_identity, &pt)?;
                out.push((Envelope { kind, ciphertext, id: item.id.clone() }, item.bulk));
            }
            Ok(out)
        });
        let Ok(envelopes) = envelopes else { return Ok(()) };
        for (env, bulk) in envelopes {
            self.in_flight.insert(env.id.clone(), bulk);
            self.send(Body::Envelope(env)).await?;
        }
        Ok(())
    }
}

pub(crate) struct Applied {
    events: Vec<Event>,
    reply_init: bool,
}

/// Stores the effects of a received message. Runs inside the decrypt transaction.
pub(crate) fn apply_content(c: &p2p_vault::rusqlite::Connection, contact_id: i64, content: Content) -> crate::Result<Applied> {
    let mut events = Vec::new();
    let mut reply_init = false;
    if content.id.len() != 16 {
        return Err(CoreError::Invalid("message id"));
    }
    if !db::mark_seen(c, contact_id, &content.id)? {
        // Duplicate (re-sent after a lost ack): acknowledge again, change nothing.
        return Ok(Applied { events, reply_init });
    }
    let local_id = db::random_id();
    let sent_at = content.sent_at_ms.min(i64::MAX as u64) as i64;
    match content.body {
        Some(content::Body::Text(text)) => {
            if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                return Ok(Applied { events, reply_init });
            }
            let expire = content.expire_secs.min(MAX_DISAPPEAR_SECS);
            db::insert_message(c, &local_id, contact_id, Some(&content.id), false, db::KIND_TEXT, &text, sent_at, db::IN_UNREAD, expire)?;
            if let Some(m) = db::message(c, &local_id)? {
                events.push(Event::Message { message: m });
            }
            events.push(Event::Contacts);
        }
        Some(content::Body::ReadReceipt(r)) => {
            for id in r.ids.iter().take(500) {
                let n = c.execute(
                    "UPDATE messages SET status = ?1 WHERE id = ?2 AND contact_id = ?3 AND outgoing = 1 AND status IN (?4, ?5)",
                    p2p_vault::rusqlite::params![db::OUT_READ, id, contact_id, db::OUT_QUEUED, db::OUT_DELIVERED],
                )?;
                if n > 0 {
                    db::start_expiry(c, id)?;
                    if let Some(m) = db::message(c, id)? {
                        events.push(Event::Message { message: m });
                    }
                }
            }
        }
        Some(content::Body::TimerUpdate(t)) => {
            if t.expire_secs <= MAX_DISAPPEAR_SECS {
                c.execute(
                    "UPDATE contacts SET disappear_secs = ?1 WHERE id = ?2",
                    p2p_vault::rusqlite::params![t.expire_secs, contact_id],
                )?;
                db::insert_message(c, &local_id, contact_id, Some(&content.id), false, db::KIND_SYSTEM, &timer_text(t.expire_secs, false), sent_at, db::IN_READ, 0)?;
                if let Some(m) = db::message(c, &local_id)? {
                    events.push(Event::Message { message: m });
                }
                events.push(Event::Contacts);
            }
        }
        Some(content::Body::FileHeader(h)) => {
            // Files only from verified contacts: an unverified one may be an impostor.
            let verified = db::contact(c, contact_id)?.is_some_and(|k| k.verified);
            let valid = h.size > 0
                && h.size <= MAX_FILE_BYTES
                && u64::from(h.chunk_count) == h.size.div_ceil(FILE_CHUNK_BYTES as u64)
                && h.sha256.len() == 32;
            if !verified || !valid || db::receiving_count(c, contact_id)? >= MAX_INCOMING_FILES {
                tracing::warn!("ignored a file offer from contact {contact_id}");
                return Ok(Applied { events, reply_init });
            }
            let name = sanitize_file_name(&h.name);
            let expire = content.expire_secs.min(MAX_DISAPPEAR_SECS);
            db::insert_message(c, &local_id, contact_id, Some(&content.id), false, db::KIND_FILE, &name, sent_at, db::IN_UNREAD, expire)?;
            db::insert_attachment(c, &local_id, &name, h.size as i64, &h.sha256, h.chunk_count, db::FILE_RECEIVING)?;
            if let Some(m) = db::message(c, &local_id)? {
                events.push(Event::Message { message: m });
            }
            events.push(Event::Contacts);
        }
        Some(content::Body::FileChunk(ch)) => {
            if let Some(m) = apply_chunk(c, contact_id, ch)?
                && let Some(view) = db::message(c, &m)?
            {
                events.push(Event::Message { message: view });
            }
        }
        Some(content::Body::SessionInit(_)) => reply_init = true,
        None => {}
    }
    Ok(Applied { events, reply_init })
}

/// Stores a file chunk; on the last one, checks the whole file's SHA-256. Returns the message
/// ID when its view changed enough to show (every 2 %, and on completion).
fn apply_chunk(c: &p2p_vault::rusqlite::Connection, contact_id: i64, ch: p2p_proto::FileChunk) -> crate::Result<Option<Vec<u8>>> {
    use sha2::Digest;
    let Some(a) = db::incoming_attachment(c, contact_id, &ch.file_id)? else { return Ok(None) };
    if a.state != db::FILE_RECEIVING || ch.index >= a.chunk_count {
        return Ok(None);
    }
    let expected_len = if ch.index + 1 == a.chunk_count {
        a.size as usize - (a.chunk_count as usize - 1) * FILE_CHUNK_BYTES
    } else {
        FILE_CHUNK_BYTES
    };
    if ch.data.len() != expected_len {
        db::set_attachment_state(c, &a.message_id, db::FILE_FAILED)?;
        return Ok(Some(a.message_id));
    }
    if !db::insert_chunk(c, &a.message_id, ch.index, &ch.data)? {
        return Ok(None);
    }
    let done = a.done_chunks + 1;
    if done < a.chunk_count {
        let step = |d: u32| u64::from(d) * 50 / u64::from(a.chunk_count);
        return Ok((step(done) != step(done - 1)).then_some(a.message_id));
    }
    let mut hash = sha2::Sha256::new();
    db::for_each_chunk(c, &a.message_id, |d| hash.update(d))?;
    let ok = hash.finalize()[..] == a.sha256[..];
    if !ok {
        tracing::warn!("file from contact {contact_id} failed its integrity check");
    }
    db::set_attachment_state(c, &a.message_id, if ok { db::FILE_RECEIVED } else { db::FILE_FAILED })?;
    Ok(Some(a.message_id))
}

/// Which outbox items to send now: everything not in flight, except that file data stops once
/// BULK_IN_FLIGHT chunks are unacknowledged. Items arrive ordered with file data last.
fn to_send<'a>(items: &'a [db::OutboxItem], in_flight: &HashMap<Vec<u8>, bool>) -> Vec<&'a db::OutboxItem> {
    let mut bulk = in_flight.values().filter(|b| **b).count();
    let mut out = Vec::new();
    for item in items.iter().filter(|i| !in_flight.contains_key(&i.id)) {
        if item.bulk {
            if bulk >= BULK_IN_FLIGHT {
                continue;
            }
            bulk += 1;
        }
        out.push(item);
    }
    out
}

#[cfg(test)]
mod window_tests {
    use super::*;

    fn item(id: u8, bulk: bool) -> db::OutboxItem {
        db::OutboxItem { id: vec![id], content: vec![], bulk }
    }

    #[test]
    fn file_chunks_are_windowed_but_texts_never_wait() {
        let items: Vec<_> = (0..3).map(|i| item(i, false)).chain((10..30).map(|i| item(i, true))).collect();
        let ids = |v: Vec<&db::OutboxItem>| v.iter().map(|i| i.id[0]).collect::<Vec<_>>();

        // Nothing in flight: all texts plus the first BULK_IN_FLIGHT chunks.
        let first = ids(to_send(&items, &HashMap::new()));
        assert_eq!(first, [0, 1, 2, 10, 11, 12, 13, 14, 15]);

        // Window full: a new text still goes out at once, no more chunks.
        let mut flight: HashMap<Vec<u8>, bool> = first.iter().map(|i| (vec![*i], *i >= 10)).collect();
        let mut with_text = items.clone();
        with_text.insert(3, item(5, false));
        assert_eq!(ids(to_send(&with_text, &flight)), [5]);

        // One chunk acknowledged (removed from the outbox and from flight): exactly one more.
        flight.remove(&vec![10]);
        let rest: Vec<_> = items.into_iter().filter(|i| i.id != [10]).collect();
        assert_eq!(ids(to_send(&rest, &flight)), [16]);
    }
}
