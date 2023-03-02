use super::*;

#[test]
fn test_key_expansion_g() {
    /*
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
    ];
    dbg!(key_expansion(&key));
    */

    // See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    // The "after xor with rcon" is what we're testing with key_expansion_g.
    // This only happens every four keys, which is what key_expansion does too.
    // The "wrd" value is the word to be used in key_expansion_g, i.e. if we're
    // trying to work out key-word 12, wrd would be key-word 11, and then we're
    // just asserting that the key-word 12 we got is the actual key-word 12.

    let wrd = 0x09cf4f3c; // Word 3 to calculate word 4
    assert_eq!(key_expansion_g(1, wrd), 0x8b84eb01);

    let wrd2 = 0xdb0bad00; // Word 19 to calculate word 20
    assert_eq!(key_expansion_g(5, wrd2), 0x3b9563b9);
}

#[test]
fn test_key_expansion() {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    // The correct key expansion output
    let correct_key = [
        0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
        0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
        0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
        0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
        0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
        0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
        0xe13f0cc8, 0xb6630ca6,
    ];

    assert_eq!(correct_key, key_expansion(&key));
}

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf, Appendix B.
#[test]
fn test_xor_with_round_key() {
    let mut input: [u32; 4] = [0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734];

    let round_key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];

    let result: [u32; 4] = [0x193de3be, 0xa0f4e22b, 0x9ac68d2a, 0xe9f84808];
    xor_with_round_key(&mut input, &round_key);
    assert_eq!(result, input);
}

#[test]
fn test_sub_bytes() {
    // The correct output from first xor with round key
    // (i.e. the input to round 1)
    let mut input: [u32; 4] = [0x193de3be, 0xa0f4e22b, 0x9ac68d2a, 0xe9f84808];

    let result = [0xd42711ae, 0xe0bf98f1, 0xb8b45de5, 0x1e415230];

    substitute_bytes(&mut input);

    assert_eq!(input, result);
}

#[test]
fn test_shift_rows() {
    // First round, after sub_bytes.
    let mut input = [0xd42711ae, 0xe0bf98f1, 0xb8b45de5, 0x1e415230];

    let result = [0xd4bf5d30, 0xe0b452ae, 0xb84111f1, 0x1e2798e5];

    shift_rows(&mut input);
    assert_eq!(input, result);
}

#[test]
fn test_permutation() {
    let mut input: [u32; 4] = [0x193de3be, 0xa0f4e22b, 0x9ac68d2a, 0xe9f84808];
    let expected_result = [0x046681e5, 0xe0cb199a, 0x48f8d37a, 0x2806264c];

    aes_permutation_tables(&mut input);
    assert_eq!(input, expected_result);
}

#[test]
fn test_entire_aes() {
    // From main.rs (and NIST paper on AES).
    let round_keys: [u32; 44] = key_expansion(&[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ]);
    let encryptor: AES = AES::new(round_keys);
    let res = (encryptor.encrypt)(
        &encryptor,
        &[
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ],
    );

    assert_eq!(
        res,
        [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32
        ]
    );
}
