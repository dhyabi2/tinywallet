//! Nano address validation.
//!
//! A Nano address is an ed25519 public key — 32 raw bytes — rendered in
//! Nano's own base32 alphabet behind a `nano_` prefix:
//!
//! - **52 characters** (260 bits): four zero padding bits, then the 256-bit
//!   public key.
//! - **8 characters** (40 bits): a 5-byte blake2b digest of the public key,
//!   byte-reversed.
//!
//! The legacy `xrb_` prefix names the same account and is still accepted.
//! Like Bitcoin and Tron, Nano addresses *are* checksummed, so a mistyped
//! address is reliably caught here rather than silently naming a different
//! account.

use blake2::digest::consts::U5;
use blake2::{Blake2b, Digest};

use crate::chain::Chain;
use crate::{Error, Result};

/// The current address prefix, and the one [`encode`] produces.
pub const PREFIX: &str = "nano_";

/// The legacy address prefix. It names the same account as [`PREFIX`].
pub const LEGACY_PREFIX: &str = "xrb_";

/// Length in bytes of a decoded Nano address (an ed25519 public key).
pub const ADDRESS_BYTES: usize = 32;

/// Nano's base32 alphabet: digits and lowercase letters without `0`, `2`,
/// `l` and `v`, which are too easily confused with other characters.
const ALPHABET: &[u8; 32] = b"13456789abcdefghijkmnopqrstuwxyz";

/// Characters encoding the padded public key: 4 zero bits plus 256 key bits.
const KEY_CHARS: usize = 52;

/// Characters encoding the 40-bit checksum.
const CHECKSUM_CHARS: usize = 8;

/// Length in bytes of the blake2b checksum.
const CHECKSUM_BYTES: usize = 5;

/// Validate a Nano address and return it trimmed.
///
/// # Errors
///
/// - [`Error::EmptyAddress`] if `address` is empty or all whitespace.
/// - [`Error::InvalidAddress`] if it lacks the `nano_` or `xrb_` prefix, is not
///   60 characters after it, uses a character outside the Nano alphabet, sets a
///   padding bit, or fails its checksum.
///
/// # Examples
///
/// ```
/// use tinywallet_crypto::address::nano;
///
/// let genesis = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3";
/// assert!(nano::validate(genesis).is_ok());
///
/// // One character changed: the checksum catches it.
/// let typo = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr4";
/// assert!(nano::validate(typo).is_err());
/// ```
pub fn validate(address: &str) -> Result<String> {
    decode(address).map(|_| address.trim().to_string())
}

/// Validate a Nano address and return its decoded 32-byte public key.
///
/// The same check as [`validate`], for a caller that needs the key rather
/// than the string — building a block, say.
///
/// # Errors
///
/// Identical to [`validate`].
///
/// # Examples
///
/// ```
/// use tinywallet_crypto::address::nano;
///
/// let key = nano::decode("nano_1111111111111111111111111111111111111111111111111111hifc8npp")?;
/// assert_eq!(key, [0u8; 32]);
/// # Ok::<(), tinywallet_crypto::Error>(())
/// ```
pub fn decode(address: &str) -> Result<[u8; ADDRESS_BYTES]> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(Error::EmptyAddress { chain: Chain::Nano });
    }
    let invalid = |reason: String| Error::InvalidAddress {
        chain: Chain::Nano,
        address: trimmed.to_string(),
        reason,
    };

    let body = trimmed
        .strip_prefix(PREFIX)
        .or_else(|| trimmed.strip_prefix(LEGACY_PREFIX))
        .ok_or_else(|| invalid(format!("expected a {PREFIX} or {LEGACY_PREFIX} prefix")))?;

    let digits = body
        .bytes()
        .map(|c| {
            ALPHABET
                .iter()
                .position(|&a| a == c)
                .and_then(|i| u8::try_from(i).ok())
                .ok_or_else(|| {
                    invalid(format!(
                        "{:?} is not in the nano base32 alphabet",
                        char::from(c)
                    ))
                })
        })
        .collect::<Result<Vec<u8>>>()?;
    if digits.len() != KEY_CHARS + CHECKSUM_CHARS {
        return Err(invalid(format!(
            "expected {} characters after the prefix, got {}",
            KEY_CHARS + CHECKSUM_CHARS,
            digits.len()
        )));
    }

    let (key_digits, checksum_digits) = digits.split_at(KEY_CHARS);
    // 52 characters carry 260 bits for a 256-bit key: the top four bits of
    // the first character are padding and must be zero.
    if key_digits[0] > 1 {
        return Err(invalid("padding bits are not zero".to_string()));
    }

    let mut key = [0u8; ADDRESS_BYTES];
    unpack(key_digits, &mut key);
    let mut checksum = [0u8; CHECKSUM_BYTES];
    unpack(checksum_digits, &mut checksum);
    if checksum != checksum_of(&key) {
        return Err(invalid("checksum mismatch".to_string()));
    }
    Ok(key)
}

/// Render a 32-byte public key as a `nano_` address.
///
/// The inverse of [`decode`]. Infallible: every 32-byte array is a
/// syntactically valid address.
///
/// # Examples
///
/// ```
/// use tinywallet_crypto::address::nano;
///
/// assert_eq!(
///     nano::encode(&[0u8; 32]),
///     "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
/// );
/// ```
#[must_use]
pub fn encode(key: &[u8; ADDRESS_BYTES]) -> String {
    let mut out = String::with_capacity(PREFIX.len() + KEY_CHARS + CHECKSUM_CHARS);
    out.push_str(PREFIX);
    pack(key, KEY_CHARS, &mut out);
    pack(&checksum_of(key), CHECKSUM_CHARS, &mut out);
    out
}

/// The 5-byte blake2b digest of `key`, byte-reversed as the address carries it.
fn checksum_of(key: &[u8; ADDRESS_BYTES]) -> [u8; CHECKSUM_BYTES] {
    let mut checksum: [u8; CHECKSUM_BYTES] = Blake2b::<U5>::digest(key).into();
    checksum.reverse();
    checksum
}

/// Unpack 5-bit `digits` into `out`, most significant bit first, discarding
/// the leading bits that do not fit — the padding bits.
fn unpack(digits: &[u8], out: &mut [u8]) {
    let padding = digits.len() * 5 - out.len() * 8;
    let bits = digits
        .iter()
        .flat_map(|&d| (0..5).rev().map(move |shift| (d >> shift) & 1))
        .skip(padding);
    for (i, bit) in bits.enumerate() {
        out[i / 8] |= bit << (7 - i % 8);
    }
}

/// Pack `bytes` into `chars` base32 characters, most significant bit first,
/// with zero padding bits in front.
fn pack(bytes: &[u8], chars: usize, out: &mut String) {
    let padding = chars * 5 - bytes.len() * 8;
    let mut bits = std::iter::repeat_n(0u8, padding).chain(
        bytes
            .iter()
            .flat_map(|&b| (0..8).rev().map(move |shift| (b >> shift) & 1)),
    );
    for _ in 0..chars {
        let digit = (0..5).fold(0usize, |acc, _| {
            (acc << 1) | usize::from(bits.next().unwrap_or(0))
        });
        out.push(char::from(ALPHABET[digit]));
    }
}

#[cfg(test)]
#[path = "nano/nano_tests.rs"]
mod test;
