mod constants;
pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
pub const ROUND_CONSTANTS: [u8; 10] = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

pub struct AES {
    round_keys: [u32; 44],
    pub encrypt: fn(&AES, &[u8]) -> [u8; 16],
    encrypt_block: fn(&AES, &mut [u32; 4]),
}

impl AES {
    pub fn new(keys: [u32; 44]) -> AES {
        AES {
            round_keys: keys,
            encrypt: aes_enc,
            encrypt_block: aes_enc_block,
        }
    }
}

/// Reformats one chunk of length 16 into a state matrix and encrypts it
fn aes_enc(aes: &AES, chunk: &[u8]) -> [u8; 16] {
    if chunk.len() != 16 {
        panic!("Error: Block length must be 16!");
    }

    // The AES matrix should be column-major, i.e.
    // 0 4  8 12
    // 1 5  9 13
    // 2 6 10 14
    // 3 7 11 15
    // We use u32s, meaning that one u32 is one column.
    // Matrix[0] is the first column, etc.
    let mut state_matrix = [0u32; 4];
    for i in 0..4 {
        let base_idx = i * 4;
        state_matrix[i] = (chunk[base_idx] as u32) << 24
            | (chunk[base_idx + 1] as u32) << 16
            | (chunk[base_idx + 2] as u32) << 8
            | chunk[base_idx + 3] as u32;
    }

    (aes.encrypt_block)(aes, &mut state_matrix);

    let mut output = [0u8; 16];
    // "Un-cast" the matrix back into 16 bytes
    for i in 0..16 {
        // Don't ask
        output[i] = (state_matrix[i / 4] >> ((3 - (i % 4)) * 8) & 0xff) as u8;
    }

    output
}

/// Encrypts one state matrix using AES
fn aes_enc_block(aes: &AES, state: &mut [u32; 4]) {
    // The first thing we do is xor the input with round key 0
    xor_with_round_key(state, &aes.round_keys[0..4]);

    // First nine rounds run the entire permutation + round key xor
    for i in 1..=9 {
        aes_permutation_tables(state);

        xor_with_round_key(state, &aes.round_keys[(i * 4)..(i + 1) * 4]);
    }

    // Tenth round we skip mix_columns
    substitute_bytes(state);
    shift_rows(state);
    xor_with_round_key(state, &aes.round_keys[40..44]);
}

// The lookup tables are made for row-major matrices, so we invert the
// `state_untouched` indices.
fn aes_permutation_tables(state: &mut [u32; 4]) {
    let state_untouched = state.clone();
    state[0] = constants::T0[(state_untouched[0] >> 24) as usize]
        ^ (constants::T1[((state_untouched[1] >> 16) & 0xff) as usize])
        ^ (constants::T2[((state_untouched[2] >> 8) & 0xff) as usize])
        ^ (constants::T3[(state_untouched[3] & 0xff) as usize]);

    state[1] = constants::T0[(state_untouched[1] >> 24) as usize]
        ^ constants::T1[((state_untouched[2] >> 16) & 0xff) as usize]
        ^ constants::T2[((state_untouched[3] >> 8) & 0xff) as usize]
        ^ constants::T3[(state_untouched[0] & 0xff) as usize];

    state[2] = constants::T0[(state_untouched[2] >> 24) as usize]
        ^ constants::T1[((state_untouched[3] >> 16) & 0xff) as usize]
        ^ constants::T2[((state_untouched[0] >> 8) & 0xff) as usize]
        ^ constants::T3[(state_untouched[1] & 0xff) as usize];

    state[3] = constants::T0[(state_untouched[3] >> 24) as usize]
        ^ constants::T1[((state_untouched[0] >> 16) & 0xff) as usize]
        ^ constants::T2[((state_untouched[1] >> 8) & 0xff) as usize]
        ^ constants::T3[(state_untouched[2] & 0xff) as usize];
}

fn xor_with_round_key(state: &mut [u32; 4], round_key: &[u32]) {
    assert!(round_key.len() == 4);

    for col in 0..4 {
        state[col] ^= round_key[col];
    }
}

/// Substitute all bytes in the state matrix, in place.
fn substitute_bytes(state: &mut [u32; 4]) {
    for col in 0..4 {
        let prev: u32 = state[col];
        state[col] = 0;
        for byte in 0..4 {
            // u32 starts from 0, then is OR:ed with last 8 bits of prev,
            // then with second 8 last bits which are shifted up by 8, etc.
            let shift_amt = byte * 8;
            state[col] |= (SBOX[((prev >> shift_amt) & 0xff) as usize] as u32) << shift_amt;
        }
    }
}

pub fn shift_rows(state: &mut [u32; 4]) {
    let state_untouched = state.clone();
    let mask_first = 0xff000000;
    let mask_second = 0x00ff0000;
    let mask_third = 0x0000ff00;
    let mask_fourth = 0x000000ff;

    // See the table on page 119 of A Graduate Course in Applied Cryptography by Dan Boneh & Victor
    // Shoup for the intuition behind this. Remember, each state index represents a _column_.
    state[0] = (state_untouched[0] & mask_first)
        | (state_untouched[1] & mask_second)
        | (state_untouched[2] & mask_third)
        | (state_untouched[3] & mask_fourth);

    state[1] = (state_untouched[1] & mask_first)
        | (state_untouched[2] & mask_second)
        | (state_untouched[3] & mask_third)
        | (state_untouched[0] & mask_fourth);

    state[2] = (state_untouched[2] & mask_first)
        | (state_untouched[3] & mask_second)
        | (state_untouched[0] & mask_third)
        | (state_untouched[1] & mask_fourth);

    state[3] = (state_untouched[3] & mask_first)
        | (state_untouched[0] & mask_second)
        | (state_untouched[1] & mask_third)
        | (state_untouched[2] & mask_fourth);
}

pub fn key_expansion_g(i: usize, word: u32) -> u32 {
    let word_as_bytes = word.to_be_bytes();
    let mut output_word = [0u8; 4];

    // Rotate left and sub the resulting byte
    for idx in 0..4 {
        output_word[idx] = SBOX[word_as_bytes[(idx + 1) % 4] as usize];
    }

    // XOR with constant. i-1 since round const 1 is in idx 0
    output_word[0] ^= ROUND_CONSTANTS[i - 1];

    u32::from_be_bytes(output_word)
}

pub fn key_expansion(key: &[u8; 16]) -> [u32; 44] {
    let mut output_keys = [0u32; 44];
    for i in 0..4 {
        let base_idx = i * 4;
        output_keys[i] = (key[base_idx] as u32) << 24
            | (key[base_idx + 1] as u32) << 16
            | (key[base_idx + 2] as u32) << 8
            | key[base_idx + 3] as u32;
    }

    //println!("{:02x?}", output_keys);
    // Append round keys 1 through 10
    for i in 1..11 {
        let base_idx = 4 * i;
        // First word of every key uses g function
        output_keys[base_idx] =
            output_keys[base_idx - 4] ^ key_expansion_g(i, output_keys[base_idx - 1]);
        output_keys[base_idx + 1] = output_keys[base_idx - 3] ^ output_keys[base_idx];
        output_keys[base_idx + 2] = output_keys[base_idx - 2] ^ output_keys[base_idx + 1];
        output_keys[base_idx + 3] = output_keys[base_idx - 1] ^ output_keys[base_idx + 2];
    }

    output_keys
}

#[cfg(test)]
mod tests;
