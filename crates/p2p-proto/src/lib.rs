//! Wire formats. Messages are defined directly with `prost` derives (no build step).
//!
//! Three layers:
//! - [`SignedPairingCode`] — exchanged out of band once, to pair two devices;
//! - [`Frame`] — everything sent inside the Noise channel;
//! - [`Content`] — the plaintext *inside* a Signal-encrypted [`Envelope`].

use prost::Message;

pub use prost::Message as ProstMessage;

/// Current protocol version (bumped on incompatible changes).
pub const PROTOCOL_VERSION: u32 = 1;

// ---------------------------------------------------------------- pairing

#[derive(Clone, PartialEq, Message)]
pub struct PairingCode {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(string, tag = "2")]
    pub display_name: String,
    /// v3 onion service ID (56 chars, no `.onion`).
    #[prost(string, tag = "3")]
    pub onion: String,
    /// Serialized libsignal `IdentityKey` (33 bytes).
    #[prost(bytes = "vec", tag = "4")]
    pub identity_key: Vec<u8>,
    /// Noise static public key (32 bytes).
    #[prost(bytes = "vec", tag = "5")]
    pub noise_static: Vec<u8>,
    /// Tor client-authorization x25519 public key (32 bytes).
    #[prost(bytes = "vec", tag = "6")]
    pub client_auth_pub: Vec<u8>,
    /// Unix seconds.
    #[prost(uint64, tag = "7")]
    pub created_at: u64,
}

/// A pairing code plus an XEdDSA signature by the identity key it contains.
#[derive(Clone, PartialEq, Message)]
pub struct SignedPairingCode {
    /// Serialized [`PairingCode`].
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

/// Domain-separation prefix for pairing-code signatures.
pub const PAIRING_SIGNATURE_CONTEXT: &[u8] = b"p2pchat/v1/pairing-code";

// ---------------------------------------------------------------- frames

#[derive(Clone, PartialEq, Message)]
pub struct Frame {
    #[prost(oneof = "frame::Body", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub body: Option<frame::Body>,
    /// Unused on the wire (padding is appended outside the protobuf by [`encode_frame`]);
    /// kept so older encoders that padded inside the message still decode.
    #[prost(bytes = "vec", tag = "15")]
    pub padding: Vec<u8>,
}

pub mod frame {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "1")]
        Hello(super::Hello),
        #[prost(message, tag = "2")]
        BundleRequest(super::BundleRequest),
        #[prost(message, tag = "3")]
        Bundle(super::Bundle),
        #[prost(message, tag = "4")]
        Envelope(super::Envelope),
        #[prost(message, tag = "5")]
        Ack(super::Ack),
        #[prost(message, tag = "6")]
        Ping(super::Ping),
        #[prost(message, tag = "7")]
        Pong(super::Ping),
    }
}

/// First frame on every connection, from both sides.
#[derive(Clone, PartialEq, Message)]
pub struct Hello {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Whether the sender holds a usable Signal session for the receiver.
    #[prost(bool, tag = "2")]
    pub has_session: bool,
}

/// Asks the peer for a fresh prekey bundle (sent by the session initiator).
#[derive(Clone, PartialEq, Message)]
pub struct BundleRequest {}

/// A Signal prekey bundle with a one-time EC prekey and a one-time ML-KEM prekey.
#[derive(Clone, PartialEq, Message)]
pub struct Bundle {
    #[prost(uint32, tag = "1")]
    pub registration_id: u32,
    #[prost(uint32, tag = "2")]
    pub device_id: u32,
    #[prost(uint32, tag = "3")]
    pub prekey_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub prekey_pub: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub signed_prekey_id: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub signed_prekey_pub: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub signed_prekey_signature: Vec<u8>,
    #[prost(uint32, tag = "8")]
    pub kyber_prekey_id: u32,
    #[prost(bytes = "vec", tag = "9")]
    pub kyber_prekey_pub: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub kyber_prekey_signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub identity_key: Vec<u8>,
}

/// A Signal-encrypted message.
#[derive(Clone, PartialEq, Message)]
pub struct Envelope {
    /// [`ENVELOPE_PREKEY`] or [`ENVELOPE_WHISPER`].
    #[prost(uint32, tag = "1")]
    pub kind: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub ciphertext: Vec<u8>,
    /// Transport-level ID used only for acknowledgement (random, 16 bytes).
    #[prost(bytes = "vec", tag = "3")]
    pub id: Vec<u8>,
}

pub const ENVELOPE_WHISPER: u32 = 1;
pub const ENVELOPE_PREKEY: u32 = 2;

#[derive(Clone, PartialEq, Message)]
pub struct Ack {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ping {
    #[prost(uint64, tag = "1")]
    pub nonce: u64,
}

// ---------------------------------------------------------------- content (inside Signal)

#[derive(Clone, PartialEq, Message)]
pub struct Content {
    /// Message ID (random, 16 bytes); used for dedup and receipts.
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    /// Sender clock, Unix milliseconds.
    #[prost(uint64, tag = "2")]
    pub sent_at_ms: u64,
    /// Disappearing-message timer in seconds (0 = off).
    #[prost(uint32, tag = "3")]
    pub expire_secs: u32,
    #[prost(oneof = "content::Body", tags = "4, 5, 6, 7, 8, 9")]
    pub body: Option<content::Body>,
}

pub mod content {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(string, tag = "4")]
        Text(String),
        /// Sent by the initiator to establish the session; carries no user data.
        #[prost(message, tag = "5")]
        SessionInit(super::SessionInit),
        #[prost(message, tag = "6")]
        ReadReceipt(super::ReadReceipt),
        #[prost(message, tag = "7")]
        TimerUpdate(super::TimerUpdate),
        /// Announces a file; its [`Content::id`] identifies the file. Chunks follow.
        #[prost(message, tag = "8")]
        FileHeader(super::FileHeader),
        #[prost(message, tag = "9")]
        FileChunk(super::FileChunk),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct SessionInit {}

#[derive(Clone, PartialEq, Message)]
pub struct ReadReceipt {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub ids: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct TimerUpdate {
    #[prost(uint32, tag = "1")]
    pub expire_secs: u32,
}

/// Largest file that can be sent (bytes).
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// File data per [`FileChunk`]. With Signal (PreKey) overhead and padding an envelope stays
/// below the largest frame bucket.
pub const FILE_CHUNK_BYTES: usize = 48 * 1024;

#[derive(Clone, PartialEq, Message)]
pub struct FileHeader {
    /// Suggested file name (no path).
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(uint64, tag = "2")]
    pub size: u64,
    #[prost(uint32, tag = "3")]
    pub chunk_count: u32,
    /// SHA-256 of the whole file, checked after reassembly.
    #[prost(bytes = "vec", tag = "4")]
    pub sha256: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct FileChunk {
    /// [`Content::id`] of the [`FileHeader`].
    #[prost(bytes = "vec", tag = "1")]
    pub file_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub index: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------- padding

/// Frame size buckets (bytes). Every frame is padded up to the next bucket.
pub const FRAME_BUCKETS: &[usize] = &[512, 2048, 8192, 32768, 65000];

/// Serializes a frame as `u32 BE protobuf length || protobuf || random padding`, padded to
/// the next size bucket, so a network observer (or Tor cell timing) cannot tell an ack from a
/// short message from a long one.
pub fn encode_frame(mut frame: Frame) -> Vec<u8> {
    frame.padding.clear();
    let body = frame.encode_to_vec();
    let used = body.len() + 4;
    let bucket = FRAME_BUCKETS.iter().copied().find(|&b| b >= used).unwrap_or(used);
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.resize(bucket, 0);
    getrandom::fill(&mut out[used..]).expect("OS RNG unavailable");
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameDecodeError {
    Truncated,
    Protobuf(prost::DecodeError),
}

impl std::fmt::Display for FrameDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameDecodeError::Truncated => f.write_str("truncated frame"),
            FrameDecodeError::Protobuf(e) => write!(f, "invalid frame: {e}"),
        }
    }
}

impl std::error::Error for FrameDecodeError {}

pub fn decode_frame(bytes: &[u8]) -> Result<Frame, FrameDecodeError> {
    let (len, rest) = bytes.split_first_chunk::<4>().ok_or(FrameDecodeError::Truncated)?;
    let len = u32::from_be_bytes(*len) as usize;
    let body = rest.get(..len).ok_or(FrameDecodeError::Truncated)?;
    Frame::decode(body).map_err(FrameDecodeError::Protobuf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_land_in_buckets() {
        for size in [0usize, 10, 400, 600, 3000, 20000] {
            let f = Frame {
                body: Some(frame::Body::Envelope(Envelope {
                    kind: ENVELOPE_WHISPER,
                    ciphertext: vec![1; size],
                    id: vec![2; 16],
                })),
                padding: vec![],
            };
            let enc = encode_frame(f.clone());
            assert!(FRAME_BUCKETS.contains(&enc.len()), "size {size} → {}", enc.len());
            let dec = decode_frame(&enc).unwrap();
            assert_eq!(dec.body, f.body);
        }
        assert_eq!(decode_frame(&[0, 0, 0, 9, 1]), Err(FrameDecodeError::Truncated));
        let ack = encode_frame(Frame { body: Some(frame::Body::Ack(Ack { id: vec![0; 16] })), padding: vec![] });
        assert_eq!(ack.len(), FRAME_BUCKETS[0]);
    }
}

#[cfg(test)]
mod robustness {
    use super::*;

    #[test]
    fn random_frames_never_panic() {
        let mut buf = vec![0u8; 70_000];
        for i in 0..20_000usize {
            let n = (i * 7919) % buf.len();
            getrandom::fill(&mut buf[..n]).unwrap();
            let _ = decode_frame(&buf[..n]);
            let _ = Content::decode(&buf[..n.min(4096)]);
            let _ = SignedPairingCode::decode(&buf[..n.min(4096)]);
        }
    }
}
