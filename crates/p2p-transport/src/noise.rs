//! Mutually authenticated, encrypted channel between two paired apps.
//!
//! Runs `Noise_IK_25519_ChaChaPoly_BLAKE2s` over the Tor stream:
//! - the **initiator** must already know the responder's static key (pinned at pairing),
//!   so it cannot be tricked into talking to anyone else;
//! - the **responder** learns the initiator's static key from the (encrypted) first
//!   handshake message and drops the connection silently unless it is a known contact.
//!
//! After the handshake, every frame is `u16 big-endian length || Noise ciphertext`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Binds the handshake to this application and protocol version.
const PROLOGUE: &[u8] = b"p2pchat/v1/noise-ik";
const NOISE_MAX_MSG: usize = 65535;
const TAG_LEN: usize = 16;
/// Largest plaintext that fits in one frame.
pub const MAX_FRAME_PLAINTEXT: usize = NOISE_MAX_MSG - TAG_LEN;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake timed out")]
    Timeout,
    #[error("peer is not an authorized contact")]
    Unauthorized,
    #[error("frame too large")]
    FrameTooLarge,
    #[error("malformed frame")]
    Malformed,
    #[error("connection closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, ChannelError>;

/// Our long-term Noise static keypair (stored in the vault).
pub struct NoiseKeypair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl NoiseKeypair {
    pub fn generate() -> NoiseKeypair {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).expect("OS RNG unavailable");
        Self::from_secret(secret)
    }

    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> NoiseKeypair {
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes();
        NoiseKeypair { secret, public }
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

fn builder<'a>(local: &'a NoiseKeypair) -> Result<snow::Builder<'a>> {
    Ok(snow::Builder::new(PATTERN.parse()?).prologue(PROLOGUE)?.local_private_key(local.secret.as_ref())?)
}

async fn read_msg<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Result<()> {
    let len = s.read_u16().await.map_err(eof_to_closed)? as usize;
    buf.resize(len, 0);
    s.read_exact(buf).await.map_err(eof_to_closed)?;
    Ok(())
}

async fn write_msg<S: AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) -> Result<()> {
    debug_assert!(msg.len() <= NOISE_MAX_MSG);
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    s.write_all(&out).await?;
    s.flush().await?;
    Ok(())
}

fn eof_to_closed(e: std::io::Error) -> ChannelError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof { ChannelError::Closed } else { e.into() }
}

/// Connects as initiator to a peer whose static key we pinned at pairing.
pub async fn initiate<S>(mut stream: S, local: &NoiseKeypair, remote_static: &[u8; 32]) -> Result<SecureChannel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let fut = async {
        let mut hs = builder(local)?.remote_public_key(remote_static)?.build_initiator()?;
        let mut buf = vec![0u8; NOISE_MAX_MSG];
        let n = hs.write_message(&[], &mut buf)?;
        write_msg(&mut stream, &buf[..n]).await?;
        let mut msg = Vec::new();
        read_msg(&mut stream, &mut msg).await?;
        hs.read_message(&msg, &mut buf)?;
        let transport = hs.into_transport_mode()?;
        Ok::<_, ChannelError>(transport)
    };
    let transport = tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await.map_err(|_| ChannelError::Timeout)??;
    Ok(SecureChannel::new(stream, transport, *remote_static))
}

/// Accepts as responder. `is_authorized` decides whether the initiator's static key belongs
/// to a known contact; if not, the connection is dropped without sending anything.
pub async fn accept<S>(
    mut stream: S,
    local: &NoiseKeypair,
    is_authorized: impl Fn(&[u8; 32]) -> bool,
) -> Result<SecureChannel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let fut = async {
        let mut hs = builder(local)?.build_responder()?;
        let mut buf = vec![0u8; NOISE_MAX_MSG];
        let mut msg = Vec::new();
        read_msg(&mut stream, &mut msg).await?;
        hs.read_message(&msg, &mut buf)?;
        let remote: [u8; 32] = hs
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(ChannelError::Unauthorized)?;
        if !is_authorized(&remote) {
            return Err(ChannelError::Unauthorized);
        }
        let n = hs.write_message(&[], &mut buf)?;
        write_msg(&mut stream, &buf[..n]).await?;
        Ok::<_, ChannelError>((hs.into_transport_mode()?, remote))
    };
    let (transport, remote) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await.map_err(|_| ChannelError::Timeout)??;
    Ok(SecureChannel::new(stream, transport, remote))
}

/// An established channel. Split it to read and write concurrently.
pub struct SecureChannel<S> {
    stream: S,
    transport: snow::TransportState,
    remote_static: [u8; 32],
}

impl<S: AsyncRead + AsyncWrite> SecureChannel<S> {
    fn new(stream: S, transport: snow::TransportState, remote_static: [u8; 32]) -> Self {
        SecureChannel { stream, transport, remote_static }
    }

    /// The peer's authenticated static key.
    pub fn remote_static(&self) -> [u8; 32] {
        self.remote_static
    }

    pub fn split(self) -> (FrameReader<S>, FrameWriter<S>) {
        let (r, w) = tokio::io::split(self.stream);
        let transport = Arc::new(Mutex::new(self.transport));
        (
            FrameReader { inner: r, transport: transport.clone(), buf: Vec::new() },
            FrameWriter { inner: w, transport, buf: vec![0u8; NOISE_MAX_MSG] },
        )
    }
}

pub struct FrameReader<S> {
    inner: ReadHalf<S>,
    transport: Arc<Mutex<snow::TransportState>>,
    buf: Vec<u8>,
}

impl<S: AsyncRead> FrameReader<S> {
    /// Reads and decrypts the next frame. Any tampering yields an error (the caller must
    /// then drop the connection: Noise nonces are now out of sync).
    pub async fn read_frame(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let len = self.inner.read_u16().await.map_err(eof_to_closed)? as usize;
        if len < TAG_LEN {
            return Err(ChannelError::Malformed);
        }
        self.buf.resize(len, 0);
        self.inner.read_exact(&mut self.buf).await.map_err(eof_to_closed)?;
        let mut out = Zeroizing::new(vec![0u8; len]);
        let n = self.transport.lock().unwrap_or_else(|e| e.into_inner()).read_message(&self.buf, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

pub struct FrameWriter<S> {
    inner: WriteHalf<S>,
    transport: Arc<Mutex<snow::TransportState>>,
    buf: Vec<u8>,
}

impl<S: AsyncWrite> FrameWriter<S> {
    pub async fn write_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_FRAME_PLAINTEXT {
            return Err(ChannelError::FrameTooLarge);
        }
        let n = self.transport.lock().unwrap_or_else(|e| e.into_inner()).write_message(plaintext, &mut self.buf)?;
        let mut out = Vec::with_capacity(n + 2);
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(&self.buf[..n]);
        self.inner.write_all(&out).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        let _ = self.inner.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair() -> (NoiseKeypair, NoiseKeypair) {
        (NoiseKeypair::generate(), NoiseKeypair::generate())
    }

    #[tokio::test]
    async fn handshake_and_bidirectional_frames() {
        let (alice, bob) = pair().await;
        let (a_io, b_io) = tokio::io::duplex(1 << 20);
        let bob_pub = bob.public();
        let alice_pub = alice.public();
        let (ra, rb) = tokio::join!(initiate(a_io, &alice, &bob_pub), accept(b_io, &bob, |k| *k == alice_pub));
        let (ca, cb) = (ra.unwrap(), rb.unwrap());
        assert_eq!(cb.remote_static(), alice_pub);
        assert_eq!(ca.remote_static(), bob_pub);
        let (mut ar, mut aw) = ca.split();
        let (mut br, mut bw) = cb.split();
        aw.write_frame(b"from alice").await.unwrap();
        bw.write_frame(b"from bob").await.unwrap();
        assert_eq!(&**br.read_frame().await.unwrap(), b"from alice");
        assert_eq!(&**ar.read_frame().await.unwrap(), b"from bob");
        let big = vec![7u8; MAX_FRAME_PLAINTEXT];
        aw.write_frame(&big).await.unwrap();
        assert_eq!(&**br.read_frame().await.unwrap(), &big[..]);
        assert!(matches!(aw.write_frame(&vec![0u8; MAX_FRAME_PLAINTEXT + 1]).await, Err(ChannelError::FrameTooLarge)));
    }

    #[tokio::test]
    async fn unknown_initiator_is_rejected_silently() {
        let (mallory, bob) = pair().await;
        let (m_io, b_io) = tokio::io::duplex(1 << 16);
        let bob_pub = bob.public();
        let known = NoiseKeypair::generate().public();
        let (rm, rb) = tokio::join!(
            initiate(m_io, &mallory, &bob_pub),
            async {
                let r = accept(b_io, &bob, |k| *k == known).await;
                // Dropping the stream here closes the connection without any reply.
                r.map(|_| ())
            }
        );
        assert!(matches!(rb, Err(ChannelError::Unauthorized)));
        assert!(rm.is_err(), "initiator must not complete a handshake with a refusing responder");
    }

    #[tokio::test]
    async fn initiator_with_wrong_pinned_key_fails() {
        // Alice pinned the wrong key for Bob (e.g. an impostor answered): handshake must fail.
        let (alice, bob) = pair().await;
        let wrong = NoiseKeypair::generate().public();
        let (a_io, b_io) = tokio::io::duplex(1 << 16);
        let (ra, rb) = tokio::join!(initiate(a_io, &alice, &wrong), accept(b_io, &bob, |_| true));
        assert!(ra.is_err() || rb.is_err());
        assert!(rb.is_err(), "responder cannot decrypt a message aimed at another key");
    }

    #[tokio::test]
    async fn tampered_frame_is_rejected() {
        let (alice, bob) = pair().await;
        let (alice_io, proxy_a) = tokio::io::duplex(1 << 16);
        let (proxy_b, bob_io) = tokio::io::duplex(1 << 16);
        // Proxy forwards bytes both ways and flips one bit in Alice→Bob traffic after the
        // handshake (IK message 1 is 98 bytes on the wire, so byte 150 is inside frame 1).
        tokio::spawn(async move {
            let (mut a_r, mut a_w) = tokio::io::split(proxy_a);
            let (mut b_r, mut b_w) = tokio::io::split(proxy_b);
            let up = async move {
                let mut n = 0usize;
                let mut byte = [0u8; 1];
                while a_r.read_exact(&mut byte).await.is_ok() {
                    n += 1;
                    if n == 150 {
                        byte[0] ^= 0x01;
                    }
                    if b_w.write_all(&byte).await.is_err() {
                        break;
                    }
                }
            };
            let down = async move {
                let _ = tokio::io::copy(&mut b_r, &mut a_w).await;
            };
            tokio::join!(up, down);
        });
        let bob_pub = bob.public();
        let alice_pub = alice.public();
        let (ra, rb) = tokio::join!(initiate(alice_io, &alice, &bob_pub), accept(bob_io, &bob, |k| *k == alice_pub));
        let (_ar, mut aw) = ra.unwrap().split();
        let (mut br, _bw) = rb.unwrap().split();
        aw.write_frame(&[0x42; 100]).await.unwrap();
        assert!(matches!(br.read_frame().await, Err(ChannelError::Noise(_))));
    }
}
