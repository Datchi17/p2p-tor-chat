//! Launches and controls a private Tor process.
//!
//! The app runs its own Tor (never the system one) with a generated configuration:
//! SOCKS and control ports bound to 127.0.0.1 on random ports, cookie authentication,
//! and `__OwningControllerProcess` so Tor exits if the app dies.
//!
//! Onion-service keys and client-authorization keys are handed to Tor over the control
//! port (`ADD_ONION`, `ONION_CLIENT_AUTH_ADD`) and are never written to disk by Tor; they
//! live only in the encrypted vault.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use base64::Engine as _;
// Unpadded: a trailing "=" would make the control-port parser read the blob as a key=value argument.
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::onion::{ServiceId, client_auth_pub_base32};

#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("tor binary not found or failed to start: {0}")]
    Spawn(std::io::Error),
    #[error("tor exited unexpectedly: {0}")]
    Exited(String),
    #[error("timed out waiting for tor: {0}")]
    Timeout(&'static str),
    #[error("tor control protocol error: {0}")]
    Control(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TorError>;

/// How to run Tor.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Path to the `tor` / `tor.exe` binary.
    pub tor_binary: PathBuf,
    /// Directory for Tor's state (consensus cache, guards). Contains no secrets of ours.
    pub data_dir: PathBuf,
    /// Optional bridge lines, e.g. `obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0`.
    pub bridges: Vec<String>,
    /// Pluggable-transport binary (lyrebird) for obfs4 / snowflake / webtunnel / meek bridges.
    pub pt_binary: Option<PathBuf>,
}

/// An onion service private key in Tor's control-port format (`ED25519-V3:<base64>`).
#[derive(Clone)]
pub struct OnionKey(Zeroizing<String>);

impl OnionKey {
    pub fn from_blob(blob: String) -> OnionKey {
        OnionKey(Zeroizing::new(blob))
    }
    pub fn blob(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for OnionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnionKey(<redacted>)")
    }
}

/// A running, controlled Tor instance.
pub struct Tor {
    child: Mutex<Child>,
    control: Mutex<ControlConn>,
    socks: SocketAddr,
    log_tail: Arc<StdMutex<VecDeque<String>>>,
}

/// Locates the Tor binary: explicit override, then next to the app executable
/// (where Tauri places bundled sidecars), then `PATH`.
pub fn find_tor_binary(override_path: Option<&Path>) -> Option<PathBuf> {
    let exe_name = if cfg!(windows) { "tor.exe" } else { "tor" };
    if let Some(p) = override_path {
        return p.is_file().then(|| p.to_path_buf());
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(exe_name)).find(|p| p.is_file())
}

/// Escapes a path for a torrc value.
fn torrc_path(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{s}\"")
}

impl Tor {
    /// Starts Tor and connects to its control port. Does not wait for bootstrap.
    pub async fn launch(cfg: &TorConfig) -> Result<Tor> {
        tokio::fs::create_dir_all(&cfg.data_dir).await?;
        restrict_permissions(&cfg.data_dir)?;
        let port_file = cfg.data_dir.join("control-port");
        let cookie_file = cfg.data_dir.join("control_auth_cookie");
        let _ = tokio::fs::remove_file(&port_file).await;

        let mut torrc = String::new();
        torrc.push_str(&format!("DataDirectory {}\n", torrc_path(&cfg.data_dir)));
        torrc.push_str("SocksPort 127.0.0.1:auto\n");
        torrc.push_str("ControlPort 127.0.0.1:auto\n");
        torrc.push_str(&format!("ControlPortWriteToFile {}\n", torrc_path(&port_file)));
        torrc.push_str("CookieAuthentication 1\n");
        torrc.push_str(&format!("CookieAuthFile {}\n", torrc_path(&cookie_file)));
        torrc.push_str(&format!("__OwningControllerProcess {}\n", std::process::id()));
        torrc.push_str("ClientOnly 1\n");
        torrc.push_str("AvoidDiskWrites 1\n");
        // Refuse SOCKS requests that carry a raw IP (they could leak DNS lookups made elsewhere).
        torrc.push_str("SafeSocks 1\n");
        torrc.push_str("Log notice stdout\n");
        if !cfg.bridges.is_empty() {
            torrc.push_str("UseBridges 1\n");
            if let Some(pt) = &cfg.pt_binary {
                torrc.push_str(&format!("ClientTransportPlugin meek_lite,obfs4,snowflake,webtunnel exec {}\n", torrc_path(pt)));
            }
            for b in &cfg.bridges {
                let line = b.trim();
                if line.is_empty() || line.contains('\n') || line.contains('\r') {
                    continue;
                }
                torrc.push_str(&format!("Bridge {line}\n"));
            }
        }
        let torrc_file = cfg.data_dir.join("torrc");
        let defaults_file = cfg.data_dir.join("torrc-defaults");
        tokio::fs::write(&torrc_file, torrc).await?;
        tokio::fs::write(&defaults_file, "").await?;

        let mut cmd = Command::new(&cfg.tor_binary);
        cmd.arg("-f")
            .arg(&torrc_file)
            .arg("--defaults-torrc")
            .arg(&defaults_file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            // CREATE_NO_WINDOW: no console window flashing up on Windows.
            cmd.creation_flags(0x0800_0000);
        }
        let mut child = cmd.spawn().map_err(TorError::Spawn)?;

        let log_tail = Arc::new(StdMutex::new(VecDeque::with_capacity(50)));
        for stream in [
            child.stdout.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child.stderr.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tail = log_tail.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stream).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "tor", "{line}");
                    let mut t = tail.lock().unwrap_or_else(|e| e.into_inner());
                    if t.len() == 50 {
                        t.pop_front();
                    }
                    t.push_back(line);
                }
            });
        }

        // Wait for Tor to publish its control port.
        let control_addr = {
            let mut waited = Duration::ZERO;
            loop {
                if let Ok(s) = tokio::fs::read_to_string(&port_file).await
                    && let Some(addr) = s.trim().strip_prefix("PORT=")
                    && let Ok(a) = addr.parse::<SocketAddr>()
                {
                    break a;
                }
                if let Some(status) = child.try_wait()? {
                    let tail = log_tail.lock().unwrap_or_else(|e| e.into_inner());
                    return Err(TorError::Exited(format!(
                        "{status}; last log: {}",
                        tail.iter().cloned().collect::<Vec<_>>().join(" | ")
                    )));
                }
                if waited > Duration::from_secs(30) {
                    return Err(TorError::Timeout("control port"));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                waited += Duration::from_millis(100);
            }
        };
        if !control_addr.ip().is_loopback() {
            return Err(TorError::Control("control port is not on loopback".into()));
        }

        let mut control = ControlConn::connect(control_addr).await?;
        let cookie = Zeroizing::new(tokio::fs::read(&cookie_file).await?);
        control.command(&format!("AUTHENTICATE {}", hex::encode(&*cookie))).await?;
        // Take ownership: Tor exits when this control connection closes.
        control.command("TAKEOWNERSHIP").await?;
        control.command("RESETCONF __OwningControllerProcess").await?;

        let socks = {
            let reply = control.command("GETINFO net/listeners/socks").await?;
            let v = reply
                .iter()
                .find_map(|l| l.strip_prefix("net/listeners/socks="))
                .ok_or_else(|| TorError::Control("no socks listener".into()))?;
            v.trim_matches('"')
                .split_whitespace()
                .next()
                .and_then(|a| a.trim_matches('"').parse::<SocketAddr>().ok())
                .ok_or_else(|| TorError::Control(format!("bad socks listener {v}")))?
        };
        if !socks.ip().is_loopback() {
            return Err(TorError::Control("socks port is not on loopback".into()));
        }

        Ok(Tor { child: Mutex::new(child), control: Mutex::new(control), socks, log_tail })
    }

    /// SOCKS5 proxy address for outgoing onion connections.
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks
    }

    /// Bootstrap progress 0–100.
    pub async fn bootstrap_progress(&self) -> Result<u8> {
        self.ensure_running().await?;
        let reply = self.control.lock().await.command("GETINFO status/bootstrap-phase").await?;
        let line = reply.first().cloned().unwrap_or_default();
        let progress = line
            .split_whitespace()
            .find_map(|w| w.strip_prefix("PROGRESS="))
            .and_then(|p| p.parse::<u8>().ok())
            .unwrap_or(0);
        Ok(progress.min(100))
    }

    /// Waits until Tor reports 100 % bootstrap, calling `on_progress` on changes.
    pub async fn wait_bootstrapped(&self, timeout: Duration, mut on_progress: impl FnMut(u8)) -> Result<()> {
        let start = tokio::time::Instant::now();
        let mut last = u8::MAX;
        loop {
            let p = self.bootstrap_progress().await?;
            if p != last {
                on_progress(p);
                last = p;
            }
            if p >= 100 {
                return Ok(());
            }
            if start.elapsed() > timeout {
                return Err(TorError::Timeout("bootstrap"));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Generates a brand-new onion service key inside Tor and returns it with its address.
    /// The service is removed immediately; publish it later with [`Tor::publish_onion`].
    pub async fn generate_onion_key(&self) -> Result<(OnionKey, ServiceId)> {
        let mut c = self.control.lock().await;
        // Port target is irrelevant: the service is deleted right away.
        let reply = Zeroizing::new(c.command("ADD_ONION NEW:ED25519-V3 Port=1,127.0.0.1:9").await?);
        let id = reply
            .iter()
            .find_map(|l| l.strip_prefix("ServiceID="))
            .ok_or_else(|| TorError::Control("no ServiceID".into()))?
            .to_string();
        let key = reply
            .iter()
            .find_map(|l| l.strip_prefix("PrivateKey="))
            .ok_or_else(|| TorError::Control("no PrivateKey".into()))?
            .to_string();
        c.command(&format!("DEL_ONION {id}")).await?;
        let service = ServiceId::parse(&id).map_err(|e| TorError::Control(e.to_string()))?;
        if !key.starts_with("ED25519-V3:") {
            return Err(TorError::Control("unexpected key type".into()));
        }
        Ok((OnionKey::from_blob(key), service))
    }

    /// Publishes (or re-publishes) our onion service, forwarding `virt_port` to `target`.
    /// Only clients whose x25519 public keys are in `authorized_clients` can find it.
    /// With no authorized clients the service is not published at all.
    pub async fn publish_onion(
        &self,
        key: &OnionKey,
        virt_port: u16,
        target: SocketAddr,
        authorized_clients: &[[u8; 32]],
    ) -> Result<Option<ServiceId>> {
        if !target.ip().is_loopback() {
            return Err(TorError::Control("onion target must be loopback".into()));
        }
        if authorized_clients.is_empty() {
            return Ok(None);
        }
        let mut cmd = Zeroizing::new(format!("ADD_ONION {} Port={virt_port},{target}", key.blob()));
        // Limit streams per rendezvous circuit: one connection is all a contact needs.
        cmd.push_str(" Flags=V3Auth,MaxStreamsCloseCircuit MaxStreams=8");
        for client in authorized_clients {
            cmd.push_str(&format!(" ClientAuthV3={}", client_auth_pub_base32(client)));
        }
        let reply = self.control.lock().await.command(&cmd).await?;
        let id = reply
            .iter()
            .find_map(|l| l.strip_prefix("ServiceID="))
            .ok_or_else(|| TorError::Control("no ServiceID".into()))?;
        Ok(Some(ServiceId::parse(id).map_err(|e| TorError::Control(e.to_string()))?))
    }

    /// Removes our published onion service (ignores "unknown service" errors).
    pub async fn unpublish_onion(&self, id: &ServiceId) -> Result<()> {
        match self.control.lock().await.command(&format!("DEL_ONION {id}")).await {
            Ok(_) => Ok(()),
            Err(TorError::Control(e)) if e.starts_with("552") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Registers our client-authorization private key for a contact's onion service.
    pub async fn add_client_auth(&self, onion: &ServiceId, secret: &[u8; 32]) -> Result<()> {
        let cmd = Zeroizing::new(format!("ONION_CLIENT_AUTH_ADD {onion} x25519:{}", B64.encode(secret)));
        self.control.lock().await.command(&cmd).await?;
        Ok(())
    }

    pub async fn remove_client_auth(&self, onion: &ServiceId) -> Result<()> {
        match self.control.lock().await.command(&format!("ONION_CLIENT_AUTH_REMOVE {onion}")).await {
            Ok(_) => Ok(()),
            Err(TorError::Control(e)) if e.starts_with("552") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Recent Tor log lines (for the diagnostics screen; contain no message data).
    pub fn log_tail(&self) -> Vec<String> {
        self.log_tail.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    async fn ensure_running(&self) -> Result<()> {
        if let Some(status) = self.child.lock().await.try_wait()? {
            return Err(TorError::Exited(status.to_string()));
        }
        Ok(())
    }

    /// Asks Tor to exit and waits briefly; kills it otherwise.
    pub async fn shutdown(&self) {
        let _ = self.control.lock().await.command("SIGNAL SHUTDOWN").await;
        let mut child = self.child.lock().await;
        if tokio::time::timeout(Duration::from_secs(5), child.wait()).await.is_err() {
            let _ = child.kill().await;
        }
    }
}

/// Minimal Tor control-protocol client (control-spec.txt §2–3).
struct ControlConn {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl ControlConn {
    async fn connect(addr: SocketAddr) -> Result<ControlConn> {
        let stream = TcpStream::connect(addr).await?;
        let (r, w) = stream.into_split();
        Ok(ControlConn { reader: BufReader::new(r), writer: w })
    }

    /// Sends one command and returns the reply lines (status code stripped).
    /// Any non-2xx final status becomes [`TorError::Control`] with the code first.
    async fn command(&mut self, cmd: &str) -> Result<Vec<String>> {
        if cmd.contains('\r') || cmd.contains('\n') {
            return Err(TorError::Control("command contains a line break".into()));
        }
        let mut line = Zeroizing::new(String::with_capacity(cmd.len() + 2));
        line.push_str(cmd);
        line.push_str("\r\n");
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;

        let mut out = Vec::new();
        loop {
            let mut raw = String::new();
            let n = tokio::time::timeout(Duration::from_secs(60), self.reader.read_line(&mut raw))
                .await
                .map_err(|_| TorError::Timeout("control reply"))??;
            if n == 0 {
                return Err(TorError::Exited("control connection closed".into()));
            }
            let l = raw.trim_end_matches(['\r', '\n']);
            if l.len() < 4 {
                return Err(TorError::Control(format!("malformed reply line {l:?}")));
            }
            let (code, sep, rest) = (&l[..3], &l[3..4], &l[4..]);
            match sep {
                "-" => out.push(rest.to_string()),
                "+" => {
                    // Data reply: lines until a lone ".".
                    out.push(rest.to_string());
                    loop {
                        let mut d = String::new();
                        if self.reader.read_line(&mut d).await? == 0 {
                            return Err(TorError::Exited("control connection closed".into()));
                        }
                        let d = d.trim_end_matches(['\r', '\n']);
                        if d == "." {
                            break;
                        }
                        out.push(d.strip_prefix('.').unwrap_or(d).to_string());
                    }
                }
                " " => {
                    if !code.starts_with('2') {
                        return Err(TorError::Control(format!("{code} {rest}")));
                    }
                    if rest != "OK" {
                        out.push(rest.to_string());
                    }
                    return Ok(out);
                }
                _ => return Err(TorError::Control(format!("malformed reply line {l:?}"))),
            }
        }
    }
}

#[cfg(unix)]
fn restrict_permissions(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_permissions(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}
