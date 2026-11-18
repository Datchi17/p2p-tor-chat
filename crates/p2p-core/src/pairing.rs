//! Pairing codes: `p2pchat1:<base64url(SignedPairingCode)>`.
//!
//! A code contains only public keys plus the onion address, and is signed by the identity key
//! it carries. The signature proves the code was not altered *after* creation; it cannot prove
//! who created it — that is what the safety-number check over a live call is for.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use p2p_proto::{PAIRING_SIGNATURE_CONTEXT, PROTOCOL_VERSION, PairingCode, ProstMessage, SignedPairingCode};
use p2p_transport::onion::ServiceId;

pub const PREFIX: &str = "p2pchat1:";
pub const MAX_NAME_CHARS: usize = 64;
const MAX_CODE_LEN: usize = 2048;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("this is not a pairing code")]
    BadFormat,
    #[error("this pairing code was made by an incompatible app version")]
    BadVersion,
    #[error("the pairing code is damaged or was tampered with")]
    BadSignature,
    #[error("the pairing code contains an invalid {0}")]
    BadField(&'static str),
}

/// The validated contents of a friend's pairing code.
#[derive(Debug, Clone)]
pub struct ParsedCode {
    pub display_name: String,
    pub onion: ServiceId,
    pub identity_key: Vec<u8>,
    pub noise_static: [u8; 32],
    pub client_auth_pub: [u8; 32],
}

/// Removes control characters and trims; used for any name coming from outside.
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).collect();
    cleaned.trim().chars().take(MAX_NAME_CHARS).collect()
}

pub fn encode(
    identity: &p2p_signal::Identity,
    display_name: &str,
    onion: &ServiceId,
    noise_static: &[u8; 32],
    client_auth_pub: &[u8; 32],
) -> Result<String, p2p_signal::Error> {
    let body = PairingCode {
        version: PROTOCOL_VERSION,
        display_name: sanitize_name(display_name),
        onion: onion.as_str().to_string(),
        identity_key: identity.public_bytes(),
        noise_static: noise_static.to_vec(),
        client_auth_pub: client_auth_pub.to_vec(),
        created_at: (crate::db::now_ms() / 1000) as u64,
    }
    .encode_to_vec();
    let signature = identity.sign(PAIRING_SIGNATURE_CONTEXT, &body)?;
    let signed = SignedPairingCode { body, signature }.encode_to_vec();
    Ok(format!("{PREFIX}{}", B64URL.encode(signed)))
}

pub fn decode(code: &str) -> Result<ParsedCode, PairingError> {
    // Accept codes pasted with spaces/line breaks (e.g. from an email).
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() > MAX_CODE_LEN {
        return Err(PairingError::BadFormat);
    }
    let b64 = compact.strip_prefix(PREFIX).ok_or(PairingError::BadFormat)?;
    let raw = B64URL.decode(b64).map_err(|_| PairingError::BadFormat)?;
    let signed = SignedPairingCode::decode(raw.as_slice()).map_err(|_| PairingError::BadFormat)?;
    let pc = PairingCode::decode(signed.body.as_slice()).map_err(|_| PairingError::BadFormat)?;
    if pc.version != PROTOCOL_VERSION {
        return Err(PairingError::BadVersion);
    }
    if !p2p_signal::is_valid_identity_key(&pc.identity_key) {
        return Err(PairingError::BadField("identity key"));
    }
    if !p2p_signal::verify_signature(&pc.identity_key, PAIRING_SIGNATURE_CONTEXT, &signed.body, &signed.signature) {
        return Err(PairingError::BadSignature);
    }
    let onion = ServiceId::parse(&pc.onion).map_err(|_| PairingError::BadField("onion address"))?;
    let noise_static: [u8; 32] = pc.noise_static.try_into().map_err(|_| PairingError::BadField("connection key"))?;
    let client_auth_pub: [u8; 32] =
        pc.client_auth_pub.try_into().map_err(|_| PairingError::BadField("access key"))?;
    if noise_static == [0u8; 32] || client_auth_pub == [0u8; 32] {
        return Err(PairingError::BadField("key"));
    }
    Ok(ParsedCode {
        display_name: sanitize_name(&pc.display_name),
        onion,
        identity_key: pc.identity_key,
        noise_static,
        client_auth_pub,
    })
}

/// Renders a code as an SVG QR image (for showing on a video call).
pub fn qr_svg(code: &str) -> String {
    match qrcode::QrCode::with_error_correction_level(code.as_bytes(), qrcode::EcLevel::M) {
        Ok(qr) => qr
            .render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(256, 256)
            .quiet_zone(true)
            .dark_color(qrcode::render::svg::Color("#000000"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build(),
        Err(_) => String::new(),
    }
}

/// Formats a 60-digit safety number as 12 groups of 5.
pub fn format_safety_number(digits: &str) -> Vec<String> {
    digits.as_bytes().chunks(5).map(|c| String::from_utf8_lossy(c).into_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code() -> (String, p2p_signal::Identity) {
        let id = p2p_signal::Identity::generate();
        let (_, onion) = p2p_transport::onion::generate_onion_identity();
        let c = encode(&id, "Alice\u{7}\n", &onion, &[1; 32], &[2; 32]).unwrap();
        (c, id)
    }

    #[test]
    fn roundtrip() {
        let (c, id) = code();
        let p = decode(&c).unwrap();
        assert_eq!(p.display_name, "Alice");
        assert_eq!(p.identity_key, id.public_bytes());
        assert_eq!(p.noise_static, [1; 32]);
        // Pasted with line breaks and spaces.
        let wrapped: String = c.chars().enumerate().flat_map(|(i, ch)| {
            if i % 40 == 39 { vec![ch, '\n', ' '] } else { vec![ch] }
        }).collect();
        assert!(decode(&wrapped).is_ok());
    }

    #[test]
    fn tampering_is_detected() {
        let (c, _) = code();
        let raw = B64URL.decode(c.strip_prefix(PREFIX).unwrap()).unwrap();
        let mut signed = SignedPairingCode::decode(raw.as_slice()).unwrap();
        let mut pc = PairingCode::decode(signed.body.as_slice()).unwrap();
        // Attacker swaps in their own onion address but keeps the victim's signature.
        let (_, evil) = p2p_transport::onion::generate_onion_identity();
        pc.onion = evil.as_str().to_string();
        signed.body = pc.encode_to_vec();
        let forged = format!("{PREFIX}{}", B64URL.encode(signed.encode_to_vec()));
        assert_eq!(decode(&forged).unwrap_err(), PairingError::BadSignature);
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(decode("hello").unwrap_err(), PairingError::BadFormat);
        assert_eq!(decode("p2pchat1:!!!").unwrap_err(), PairingError::BadFormat);
        assert_eq!(decode(&format!("p2pchat1:{}", "A".repeat(5000))).unwrap_err(), PairingError::BadFormat);
    }

    #[test]
    fn qr_renders() {
        let (c, _) = code();
        let svg = qr_svg(&c);
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
    }
}

#[cfg(test)]
mod robustness {
    use super::*;

    #[test]
    fn random_codes_never_panic() {
        let (c, _) = {
            let id = p2p_signal::Identity::generate();
            let (_, onion) = p2p_transport::onion::generate_onion_identity();
            (encode(&id, "Fuzz", &onion, &[1; 32], &[2; 32]).unwrap(), id)
        };
        let raw = B64URL.decode(c.strip_prefix(PREFIX).unwrap()).unwrap();
        let mut rnd = [0u8; 4];
        for _ in 0..5000 {
            let mut m = raw.clone();
            getrandom::fill(&mut rnd).unwrap();
            let pos = u16::from_le_bytes([rnd[0], rnd[1]]) as usize % m.len();
            m[pos] ^= rnd[2] | 1;
            let code = format!("{PREFIX}{}", B64URL.encode(&m));
            // Any single-byte change must be rejected (bad format or bad signature), never accepted.
            assert!(decode(&code).is_err(), "mutated code accepted at byte {pos}");
        }
        for _ in 0..5000 {
            let mut junk = vec![0u8; (rnd[3] as usize) * 4];
            getrandom::fill(&mut junk).unwrap();
            getrandom::fill(&mut rnd).unwrap();
            let _ = decode(&format!("{PREFIX}{}", B64URL.encode(&junk)));
            let _ = decode(&String::from_utf8_lossy(&junk));
        }
    }
}
