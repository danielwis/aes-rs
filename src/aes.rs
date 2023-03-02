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

pub type Word = [u8; 4];

pub struct AES {
    round_keys: [[u8; 4]; 44],
    pub encrypt: fn(&AES, &[u8]) -> [u8; 16],
    encrypt_block: fn(&AES, &mut [[u8; 4]; 4]),
    permutation: fn(&mut [[u8; 4]; 4]),
}

impl AES {
    pub fn new(keys: [Word; 44]) -> AES {
        AES {
            round_keys: keys,
            encrypt: aes_enc,
            encrypt_block: aes_enc_block,
            permutation: aes_permutation,
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
    // state_matrix[i][j] is col i, row j, meaning that
    // when we read in [0][0], [0][1] etc, we read column by column
    let mut state_matrix = [[0u8; 4]; 4];
    for i in 0..16 {
        state_matrix[i / 4][i % 4] = chunk[i];
    }

    (aes.encrypt_block)(aes, &mut state_matrix);

    let mut output = [0u8; 16];
    for i in 0..16 {
        output[i] = state_matrix[i / 4][i % 4];
    }

    output
}

fn xor_vecs_into(a: &[u8; 4], b: &[u8; 4], c: &[u8; 4], d: &[u8; 4], res: &mut [u8; 4]) {
    for i in 0..4 {
        res[i] = a[i] ^ b[i] ^ c[i] ^ d[i];
    }
}

pub fn aes_permutation(state: &mut [[u8; 4]; 4]) {
    substitute_bytes(state);
    shift_rows(state);
    mix_columns(state);
}

fn aes_permutation_tables(state: &mut [[u8; 4]; 4]) {
    let state_untouched = state.clone();

    xor_vecs_into(
        &constants::PERMUTATION_TABLES[0][state_untouched[0][0] as usize],
        &constants::PERMUTATION_TABLES[1][state_untouched[1][1] as usize],
        &constants::PERMUTATION_TABLES[2][state_untouched[2][2] as usize],
        &constants::PERMUTATION_TABLES[3][state_untouched[3][3] as usize],
        &mut state[0],
    );
    xor_vecs_into(
        &constants::PERMUTATION_TABLES[0][state_untouched[1][0] as usize],
        &constants::PERMUTATION_TABLES[1][state_untouched[2][1] as usize],
        &constants::PERMUTATION_TABLES[2][state_untouched[3][2] as usize],
        &constants::PERMUTATION_TABLES[3][state_untouched[0][3] as usize],
        &mut state[1],
    );
    xor_vecs_into(
        &constants::PERMUTATION_TABLES[0][state_untouched[2][0] as usize],
        &constants::PERMUTATION_TABLES[1][state_untouched[3][1] as usize],
        &constants::PERMUTATION_TABLES[2][state_untouched[0][2] as usize],
        &constants::PERMUTATION_TABLES[3][state_untouched[1][3] as usize],
        &mut state[2],
    );
    xor_vecs_into(
        &constants::PERMUTATION_TABLES[0][state_untouched[3][0] as usize],
        &constants::PERMUTATION_TABLES[1][state_untouched[0][1] as usize],
        &constants::PERMUTATION_TABLES[2][state_untouched[1][2] as usize],
        &constants::PERMUTATION_TABLES[3][state_untouched[2][3] as usize],
        &mut state[3],
    );
}

/// Encrypts one state matrix using AES
fn aes_enc_block(aes: &AES, state: &mut [[u8; 4]; 4]) {
    // The first thing we do is xor the input with round key 0
    xor_with_round_key(state, &aes.round_keys[0..4]);

    // First nine rounds run the entire permutation + round key xor
    for i in 1..=9 {
        (aes.permutation)(state);

        xor_with_round_key(state, &aes.round_keys[(i * 4)..(i + 1) * 4]);
    }

    // Tenth round we skip mix_columns
    substitute_bytes(state);
    shift_rows(state);
    xor_with_round_key(state, &aes.round_keys[40..44]);
}

// Thanks to https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
// Bit shifting has to be &-ed as otherwise it expands (e.g. to an u16 or u32)
pub fn finite_field_mult(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;

    for _ in 0..8 {
        // 0*0 is just 0. However, this makes a timing attack possible.
        if a == 0 || b == 0 {
            return p;
        }

        if b & 1 == 1 {
            p ^= a;
        }

        b = (b >> 1) & 0xff;

        let carry: bool = (a & 0x80) == 0x80;

        a = (a << 1) & 0xff;

        if carry {
            a ^= 0x1b;
        }
    }

    return p;
}

fn xor_with_round_key(state: &mut [[u8; 4]; 4], round_key: &[[u8; 4]]) {
    assert!(round_key.len() == 4);

    for col in 0..4 {
        for row in 0..4 {
            state[col][row] ^= round_key[col][row];
        }
    }
}

/// Substitute all bytes in the state matrix, in place.
fn substitute_bytes(state: &mut [[u8; 4]; 4]) {
    for col in 0..4 {
        for row in 0..4 {
            state[col][row] = SBOX[state[col][row] as usize]
        }
    }
}

pub fn shift_rows(state: &mut [[u8; 4]; 4]) {
    for row in 1..4 {
        // Get a copy of the row
        let mut curr_row = [0u8; 4];
        for col in 0..4 {
            curr_row[col] = state[col][row];
        }

        // Shift row 1 by 1, row 2 by 2, and row 3 by 3,
        // using the copy of the row.
        for col in 0..4 {
            state[col][row] = curr_row[(col + row) % 4];
        }
    }
}

pub fn mix_columns(state: &mut [[u8; 4]; 4]) {
    // The matrix we multiply with is
    // 2 3 1 1
    // 1 2 3 1
    // 1 1 2 3
    // 3 1 1 2
    // i.e. the sequence [2, 3, 1, 1] shifted one step
    // right for every row. This means that each column
    // in our state can be "shifted down" by one while
    // we just multiply with the fixed constants of the top row.

    for col in 0..4 {
        // Preserve the column since we'll be changing it
        // in the matrix multiplication
        let mut intact_column = [0u8; 4];
        for row in 0..4 {
            intact_column[row] = state[col][row];
        }

        for row in 0..4 {
            state[col][row] = finite_field_mult(intact_column[row], 0x2)
                ^ finite_field_mult(intact_column[(row + 1) % 4], 0x3)
                ^ finite_field_mult(intact_column[(row + 2) % 4], 0x1)
                ^ finite_field_mult(intact_column[(row + 3) % 4], 0x1);
        }
    }
}

fn word_xor(w1: &Word, w2: &Word) -> Word {
    let mut result = [0u8; 4]; // Word but zero-initialised

    for i in 0..4 {
        result[i] = w1[i] ^ w2[i];
    }

    result
}

pub fn key_expansion_g(i: usize, word: Word) -> Word {
    let mut output_word = [0u8; 4];

    // Rotate left and sub the resulting byte
    for idx in 0..4 {
        output_word[idx] = SBOX[word[(idx + 1) % 4] as usize];
    }

    // XOR with constant. i-1 since round const 1 is in idx 0
    output_word[0] ^= ROUND_CONSTANTS[i - 1];

    output_word
}

pub fn key_expansion(key: &[u8; 16]) -> [Word; 44] {
    let mut input_key = [[0u8; 4]; 4]; // [Word; 4]
    let mut output_keys = [[0u8; 4]; 44]; // [Word; 44]

    for i in 0..16 {
        input_key[i / 4][i % 4] = key[i];
    }

    // Append round key 0
    for i in 0..4 {
        output_keys[i] = input_key[i];
    }

    // Append round keys 1 through 10
    for i in 4..44 {
        // First word of every key uses g function
        if i % 4 == 0 {
            output_keys[i] = word_xor(
                &output_keys[i - 4],
                &key_expansion_g(i / 4, output_keys[i - 1]),
            );
        } else {
            output_keys[i] = word_xor(&output_keys[i - 4], &output_keys[i - 1]);
        }
    }

    output_keys
}

#[cfg(test)]
mod tests;
