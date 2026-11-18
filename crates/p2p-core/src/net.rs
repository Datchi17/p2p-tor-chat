//! Network supervisor: Tor, our onion service, the listener, per-contact dialers, and the
//! table of live peer connections.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2p_transport::noise;
use p2p_transport::onion::ServiceId;
use p2p_transport::tor::{Tor, TorConfig, find_tor_binary};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio::task::JoinHandle;

use crate::db;
use crate::peer::{self, Cmd};
use crate::{CoreError, Event, Inner};

/// Virtual port of our onion service.
pub(crate) const ONION_PORT: u16 = 7001;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(600);
const DIAL_TIMEOUT: Duration = Duration::from_secs(120);
const MIN_BACKOFF: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MAX_PENDING_HANDSHAKES: usize = 8;

#[derive(Default)]
pub(crate) enum NetSlot {
    #[default]
    Off,
    Starting(JoinHandle<()>),
    Running(Arc<Network>),
}

type Dialers = HashMap<i64, (Arc<Notify>, JoinHandle<()>)>;

pub(crate) struct ConnHandle {
    pub conn_id: u64,
    /// Noise static key of the side that dialed this connection.
    pub initiator: [u8; 32],
    pub cmd: mpsc::Sender<Cmd>,
}

pub(crate) struct Network {
    pub tor: Tor,
    pub noise: Arc<noise::NoiseKeypair>,
    listen: SocketAddr,
    conns: Mutex<HashMap<i64, ConnHandle>>,
    dialers: Mutex<Dialers>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    published: tokio::sync::Mutex<Option<ServiceId>>,
    next_conn_id: AtomicU64,
}

pub(crate) fn jitter(max: Duration) -> Duration {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    let ms = max.as_millis().max(1) as u64;
    Duration::from_millis(u64::from_le_bytes(b) % ms)
}

impl Network {
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Registers a connection, applying the tie-break both sides agree on: keep the
    /// connection dialed by the peer with the smaller Noise key; for the same dialer, prefer
    /// the newest. Returns false if this connection lost and must close.
    pub fn register(&self, inner: &Inner, contact_id: i64, h: ConnHandle) -> bool {
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = conns.get(&contact_id) {
            let keep_new = h.initiator <= existing.initiator;
            if !keep_new {
                return false;
            }
            let _ = existing.cmd.try_send(Cmd::Close);
            conns.insert(contact_id, h);
            return true;
        }
        conns.insert(contact_id, h);
        drop(conns);
        inner.emit(Event::Presence { contact_id, online: true });
        true
    }

    pub fn unregister(&self, inner: &Inner, contact_id: i64, conn_id: u64) {
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if conns.get(&contact_id).is_some_and(|h| h.conn_id == conn_id) {
            conns.remove(&contact_id);
            drop(conns);
            inner.emit(Event::Presence { contact_id, online: false });
            self.wake_dialer(contact_id);
        }
    }

    fn is_connected(&self, contact_id: i64) -> bool {
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&contact_id)
    }

    fn wake_dialer(&self, contact_id: i64) {
        if let Some((n, _)) = self.dialers.lock().unwrap_or_else(|e| e.into_inner()).get(&contact_id) {
            n.notify_one();
        }
    }

    fn online(&self) -> HashSet<i64> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect()
    }

    /// (Re)publishes our onion service with the current set of authorized contacts.
    async fn republish(&self, inner: &Inner) -> Result<(), CoreError> {
        let (key, clients) = inner.with(|u| {
            let clients = db::contacts(u.vault.conn())?.into_iter().map(|c| c.client_auth_pub).collect::<Vec<_>>();
            Ok((u.onion_key.clone(), clients))
        })?;
        let mut published = self.published.lock().await;
        if let Some(id) = published.take() {
            self.tor.unpublish_onion(&id).await.map_err(|e| CoreError::Internal(e.to_string()))?;
        }
        *published = self
            .tor
            .publish_onion(&key, ONION_PORT, self.listen, &clients)
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Registers our client-auth key with Tor for every contact's onion service.
    async fn sync_client_auth(&self, inner: &Inner) -> Result<(), CoreError> {
        let (secret, onions) = inner.with(|u| {
            let onions = db::contacts(u.vault.conn())?.into_iter().map(|c| c.onion).collect::<Vec<_>>();
            Ok((u.client_auth.secret_bytes(), onions))
        })?;
        for onion in onions {
            if let Ok(id) = ServiceId::parse(&onion) {
                self.tor.add_client_auth(&id, &secret).await.map_err(|e| CoreError::Internal(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn ensure_dialers(self: &Arc<Self>, inner: &Arc<Inner>) {
        let Ok(ids) = inner.with(|u| Ok(db::contacts(u.vault.conn())?.into_iter().map(|c| c.id).collect::<Vec<_>>()))
        else {
            return;
        };
        let mut dialers = self.dialers.lock().unwrap_or_else(|e| e.into_inner());
        for id in ids {
            dialers.entry(id).or_insert_with(|| {
                let notify = Arc::new(Notify::new());
                let h = tokio::spawn(dialer(inner.clone(), self.clone(), id, notify.clone()));
                (notify, h)
            });
        }
    }

    async fn shutdown(&self) {
        for (_, (_, h)) in self.dialers.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            h.abort();
        }
        for h in self.tasks.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            h.abort();
        }
        for (_, c) in self.conns.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            let _ = c.cmd.try_send(Cmd::Close);
        }
        self.tor.shutdown().await;
    }
}

/// Starts networking in the background (returns immediately).
pub(crate) async fn start(inner: Arc<Inner>) {
    let mut slot = inner.net.lock().await;
    if !matches!(*slot, NetSlot::Off) {
        return;
    }
    let task_inner = inner.clone();
    *slot = NetSlot::Starting(tokio::spawn(async move {
        // Keep trying (e.g. no internet at launch): 15 s, 30 s, 60 s … capped at 5 min.
        let mut delay = Duration::from_secs(15);
        loop {
            match run_startup(task_inner.clone()).await {
                Ok(()) => return,
                Err(CoreError::Locked) => return,
                Err(e) => {
                    tracing::warn!("network startup failed: {e}");
                    task_inner.emit(Event::Tor {
                        progress: 0,
                        ready: false,
                        error: Some(format!("{e} — retrying in {} s", delay.as_secs())),
                    });
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(MAX_BACKOFF);
                }
            }
        }
    }));
}

async fn run_startup(inner: Arc<Inner>) -> Result<(), CoreError> {
    let (bridges, noise) = inner.with(|u| Ok((db::settings_get(u.vault.conn())?.bridges, u.noise.clone())))?;
    let tor_binary = find_tor_binary(inner.cfg.tor_binary.as_deref())
        .ok_or(CoreError::Internal("Tor was not found. Reinstall the app.".into()))?;
    let cfg = TorConfig {
        tor_binary,
        data_dir: inner.cfg.data_dir.join("tor"),
        bridges,
        pt_binary: inner.cfg.pt_binary.clone(),
    };
    inner.emit(Event::Tor { progress: 0, ready: false, error: None });
    let tor = Tor::launch(&cfg).await.map_err(|e| CoreError::Internal(e.to_string()))?;
    let ev = inner.clone();
    tor.wait_bootstrapped(BOOTSTRAP_TIMEOUT, move |p| ev.emit(Event::Tor { progress: p, ready: false, error: None }))
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?;

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| CoreError::Internal(e.to_string()))?;
    let listen = listener.local_addr().map_err(|e| CoreError::Internal(e.to_string()))?;
    let net = Arc::new(Network {
        tor,
        noise,
        listen,
        conns: Mutex::new(HashMap::new()),
        dialers: Mutex::new(HashMap::new()),
        tasks: Mutex::new(Vec::new()),
        published: tokio::sync::Mutex::new(None),
        next_conn_id: AtomicU64::new(1),
    });
    net.sync_client_auth(&inner).await?;
    net.republish(&inner).await?;
    {
        let mut tasks = net.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.push(tokio::spawn(accept_loop(inner.clone(), net.clone(), listener)));
        tasks.push(tokio::spawn(maintenance_loop(inner.clone())));
    }
    net.ensure_dialers(&inner);

    let mut slot = inner.net.lock().await;
    *slot = NetSlot::Running(net);
    drop(slot);
    inner.emit(Event::Tor { progress: 100, ready: true, error: None });
    Ok(())
}

pub(crate) async fn stop(inner: &Inner) {
    let old = std::mem::take(&mut *inner.net.lock().await);
    match old {
        NetSlot::Off => {}
        // Aborting drops the Tor handle, and Tor is killed on drop.
        NetSlot::Starting(h) => h.abort(),
        NetSlot::Running(net) => net.shutdown().await,
    }
}

async fn running(inner: &Inner) -> Option<Arc<Network>> {
    match &*inner.net.lock().await {
        NetSlot::Running(n) => Some(n.clone()),
        _ => None,
    }
}

pub(crate) async fn contacts_changed(inner: &Arc<Inner>) {
    let Some(net) = running(inner).await else { return };
    if let Err(e) = net.sync_client_auth(inner).await {
        tracing::warn!("client auth sync failed: {e}");
    }
    if let Err(e) = net.republish(inner).await {
        tracing::warn!("republish failed: {e}");
    }
    net.ensure_dialers(inner);
}

pub(crate) async fn contact_removed(inner: &Arc<Inner>, contact: &db::Contact) {
    let Some(net) = running(inner).await else { return };
    if let Some((_, h)) = net.dialers.lock().unwrap_or_else(|e| e.into_inner()).remove(&contact.id) {
        h.abort();
    }
    if let Some(c) = net.conns.lock().unwrap_or_else(|e| e.into_inner()).remove(&contact.id) {
        let _ = c.cmd.try_send(Cmd::Close);
    }
    if let Ok(id) = ServiceId::parse(&contact.onion) {
        let _ = net.tor.remove_client_auth(&id).await;
    }
    if let Err(e) = net.republish(inner).await {
        tracing::warn!("republish failed: {e}");
    }
}

/// New outgoing data for a contact: flush on the live connection, or dial now.
pub(crate) async fn kick(inner: &Inner, contact_id: i64) {
    let Some(net) = running(inner).await else { return };
    let sender = net.conns.lock().unwrap_or_else(|e| e.into_inner()).get(&contact_id).map(|c| c.cmd.clone());
    match sender {
        Some(tx) => {
            let _ = tx.try_send(Cmd::Kick);
        }
        None => net.wake_dialer(contact_id),
    }
}

pub(crate) async fn online_contacts(inner: &Inner) -> HashSet<i64> {
    running(inner).await.map(|n| n.online()).unwrap_or_default()
}

pub(crate) async fn tor_log(inner: &Inner) -> Vec<String> {
    running(inner).await.map(|n| n.tor.log_tail()).unwrap_or_default()
}

async fn accept_loop(inner: Arc<Inner>, net: Arc<Network>, listener: TcpListener) {
    let permits = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let Ok((stream, peer)) = listener.accept().await else { continue };
        // Tor connects to us from loopback; anything else is not Tor.
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
        let (inner, net) = (inner.clone(), net.clone());
        tokio::spawn(async move {
            let lookup_inner = inner.clone();
            let known = move |k: &[u8; 32]| {
                lookup_inner.with(|u| Ok(db::contact_by_noise(u.vault.conn(), k)?.is_some())).unwrap_or(false)
            };
            let chan = match noise::accept(stream, &net.noise, known).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!("inbound handshake rejected: {e}");
                    return;
                }
            };
            drop(permit);
            let remote = chan.remote_static();
            let Ok(Some(contact)) = inner.with(|u| Ok(db::contact_by_noise(u.vault.conn(), &remote)?)) else { return };
            peer::run(inner, net, contact.id, chan, remote).await;
        });
    }
}

async fn dialer(inner: Arc<Inner>, net: Arc<Network>, contact_id: i64, notify: Arc<Notify>) {
    let mut backoff = MIN_BACKOFF;
    // Small random delay so both sides don't always dial at the same instant.
    tokio::time::sleep(jitter(Duration::from_secs(3))).await;
    loop {
        if net.is_connected(contact_id) {
            let _ = tokio::time::timeout(Duration::from_secs(60), notify.notified()).await;
            continue;
        }
        let Ok(Some(contact)) = inner.with(|u| Ok(db::contact(u.vault.conn(), contact_id)?)) else { return };
        let Ok(onion) = ServiceId::parse(&contact.onion) else { return };
        let attempt = async {
            let stream = tokio_socks::tcp::Socks5Stream::connect(net.tor.socks_addr(), (onion.hostname().as_str(), ONION_PORT))
                .await
                .map_err(|e| e.to_string())?;
            noise::initiate(stream, &net.noise, &contact.noise_static).await.map_err(|e| e.to_string())
        };
        match tokio::time::timeout(DIAL_TIMEOUT, attempt).await {
            Ok(Ok(chan)) => {
                backoff = MIN_BACKOFF;
                let me = net.noise.public();
                tokio::spawn(peer::run(inner.clone(), net.clone(), contact_id, chan, me));
                // Give the connection time to register before checking again.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Ok(Err(e)) => {
                tracing::debug!("dial {contact_id} failed: {e}");
                wait_backoff(&notify, &mut backoff).await;
            }
            Err(_) => {
                tracing::debug!("dial {contact_id} timed out");
                wait_backoff(&notify, &mut backoff).await;
            }
        }
    }
}

async fn wait_backoff(notify: &Notify, backoff: &mut Duration) {
    let wait = *backoff + jitter(*backoff / 2);
    let _ = tokio::time::timeout(wait, notify.notified()).await;
    *backoff = (*backoff * 2).min(MAX_BACKOFF);
}

async fn maintenance_loop(inner: Arc<Inner>) {
    let mut tick = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        tick += 1;
        if let Ok(gone) = inner.with(|u| Ok(db::expire(u.vault.conn())?))
            && !gone.is_empty()
        {
            let mut by_contact: HashMap<i64, Vec<String>> = HashMap::new();
            for (c, id) in gone {
                by_contact.entry(c).or_default().push(id);
            }
            for (contact_id, ids) in by_contact {
                inner.emit(Event::Deleted { contact_id, ids });
            }
            inner.emit(Event::Contacts);
        }
        if tick.is_multiple_of(720) {
            let _ = inner.with(|u| Ok(p2p_signal::maintenance(u.vault.conn(), &u.identity)?));
        }
    }
}
