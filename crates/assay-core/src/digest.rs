use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

pub fn sha512_hex(bytes: &[u8]) -> String {
    let digest = Sha512::digest(bytes);
    hex_encode(&digest)
}

pub fn sha512_sri(bytes: &[u8]) -> String {
    let digest = Sha512::digest(bytes);
    format!("sha512-{}", BASE64_STANDARD.encode(digest))
}

/// Parses an npm SRI integrity string (`sha512-<base64>`) into lowercase hex.
/// Returns `None` if it is not a valid SHA-512 SRI string.
pub fn parse_sha512_sri(sri: &str) -> Option<String> {
    for token in sri.split_whitespace() {
        if let Some(b64) = token.strip_prefix("sha512-") {
            if let Ok(decoded) = BASE64_STANDARD.decode(b64) {
                if decoded.len() == 64 {
                    return Some(hex_encode(&decoded));
                }
            }
        }
    }
    None
}

/// Computes the Git blob object identifier: SHA-1("blob " + len + "\0" + bytes).
/// Used strictly as a lookup key in a Git tree; equality is always confirmed via SHA-256.
pub fn git_blob_sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    let header = format!("blob {}\0", bytes.len());
    hasher.update(header.as_bytes());
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests_and_git_blob() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // `printf "hello\n" | git hash-object --stdin`
        assert_eq!(
            git_blob_sha1_hex(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
        let sri = sha512_sri(b"assay");
        assert_eq!(parse_sha512_sri(&sri), Some(sha512_hex(b"assay")));
        assert_eq!(parse_sha512_sri("sha256-AAAA"), None);
    }
}
