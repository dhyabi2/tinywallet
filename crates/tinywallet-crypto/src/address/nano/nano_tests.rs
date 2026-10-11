//! Unit tests for Nano address validation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{ADDRESS_BYTES, decode, encode, validate};
use crate::{Chain, Error};

/// A real mainnet account.
const ACCOUNT: &str = "nano_1434j1n4sin4cefs5njibag4tsmo596fmg3s6bdogtod3ndmdfez5yuebrh9";
/// The genesis account, whose public key is published.
const GENESIS: &str = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3";
/// The genesis public key, E89208DD…A65093BA.
const GENESIS_KEY: [u8; ADDRESS_BYTES] = [
    0xe8, 0x92, 0x08, 0xdd, 0x03, 0x8f, 0xbb, 0x26, 0x99, 0x87, 0x68, 0x96, 0x21, 0xd5, 0x22, 0x92,
    0xae, 0x9c, 0x35, 0x94, 0x1a, 0x74, 0x84, 0x75, 0x6e, 0xcc, 0xed, 0x92, 0xa6, 0x50, 0x93, 0xba,
];
/// The burn address: the all-zero public key.
const BURN: &str = "nano_1111111111111111111111111111111111111111111111111111hifc8npp";

#[test]
fn accepts_real_addresses() {
    for addr in [ACCOUNT, GENESIS, BURN] {
        assert_eq!(validate(addr).unwrap(), addr);
    }
}

#[test]
fn accepts_the_legacy_xrb_prefix() {
    let legacy = GENESIS.replacen("nano_", "xrb_", 1);
    assert_eq!(validate(&legacy).unwrap(), legacy);
    assert_eq!(decode(&legacy).unwrap(), decode(GENESIS).unwrap());
}

#[test]
fn trims_surrounding_whitespace() {
    assert_eq!(validate(&format!("  {GENESIS}\n")).unwrap(), GENESIS);
}

#[test]
fn rejects_an_empty_address() {
    assert_eq!(
        validate("  ").unwrap_err(),
        Error::EmptyAddress { chain: Chain::Nano }
    );
}

#[test]
fn decode_returns_the_public_key() {
    assert_eq!(decode(BURN).unwrap(), [0u8; ADDRESS_BYTES]);
    assert_eq!(decode(GENESIS).unwrap(), GENESIS_KEY);
}

#[test]
fn rejects_a_mistyped_address_via_its_checksum() {
    // The last character sits in the checksum; changing it leaves the key
    // intact, so only the checksum can catch it.
    let typo = format!("{}8", &ACCOUNT[..ACCOUNT.len() - 1]);
    assert_ne!(typo, ACCOUNT, "the fixture must actually differ");
    assert_invalid(&typo, "checksum");
}

#[test]
fn rejects_a_mistyped_public_key_via_its_checksum() {
    let mut chars: Vec<char> = GENESIS.chars().collect();
    chars[10] = if chars[10] == 'a' { 'b' } else { 'a' };
    let typo: String = chars.into_iter().collect();
    assert_invalid(&typo, "checksum");
}

#[test]
fn rejects_a_missing_or_foreign_prefix() {
    for bad in [
        &ACCOUNT["nano_".len()..],
        &ACCOUNT.replacen("nano_", "ban_", 1),
        &ACCOUNT.replacen("nano_", "NANO_", 1),
    ] {
        assert_invalid(bad, "prefix");
    }
}

#[test]
fn rejects_the_wrong_length() {
    assert_invalid(&ACCOUNT[..ACCOUNT.len() - 1], "60");
    assert_invalid(&format!("{ACCOUNT}1"), "60");
}

#[test]
fn rejects_characters_outside_the_nano_alphabet() {
    // `0`, `2`, `l` and `v` are excluded, and the alphabet is lowercase only.
    for bad in ['0', '2', 'l', 'v', 'A'] {
        let addr = format!("{}{bad}{}", &ACCOUNT[..20], &ACCOUNT[21..]);
        assert_invalid(&addr, "alphabet");
    }
}

#[test]
fn rejects_nonzero_padding_bits() {
    // `4` differs from `1` only in the padding bits, so the key and checksum
    // stay valid and the padding check is the only thing that can fail.
    let padded = ACCOUNT.replacen("nano_1", "nano_4", 1);
    assert_invalid(&padded, "padding");
}

#[test]
fn encode_and_decode_round_trip() {
    assert_eq!(encode(&decode(ACCOUNT).unwrap()), ACCOUNT);
    assert_eq!(encode(&decode(GENESIS).unwrap()), GENESIS);
    let mut bytes = [0u8; ADDRESS_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap().wrapping_mul(37);
    }
    assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    assert_eq!(
        encode(&[0xff; ADDRESS_BYTES]),
        "nano_3zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzc3yoon41"
    );
}

#[test]
fn decode_rejects_exactly_what_validate_rejects() {
    for input in ["", "   ", "nano_", &ACCOUNT[..ACCOUNT.len() - 1], ACCOUNT] {
        assert_eq!(
            validate(input).is_err(),
            decode(input).is_err(),
            "validate and decode disagreed on {input:?}"
        );
    }
}

fn assert_invalid(address: &str, reason_part: &str) {
    match validate(address).unwrap_err() {
        Error::InvalidAddress { chain, reason, .. } => {
            assert_eq!(chain, Chain::Nano);
            assert!(
                reason.contains(reason_part),
                "reason for {address:?} was {reason:?}"
            );
        }
        other => panic!("expected InvalidAddress for {address:?}, got {other:?}"),
    }
}
