pub fn create_lookup_tables() -> Vec<Vec<Vec<u8>>> {
    let M = [
        [0x2, 0x1, 0x1, 0x3],
        [0x3, 0x2, 0x1, 0x1],
        [0x1, 0x3, 0x2, 0x1],
        [0x1, 0x1, 0x3, 0x2],
    ];
    let mut T = vec![vec![vec![0u8; 4]; 256]; 4]; // 4 tables of 256 4-byte vectors each
    for i in 0..4 {
        let mclone = M[i].clone();
        for byte in 0..=255 {
            for j in 0..4 {
                T[i][byte][j] = finite_field_mult(mclone[j], SBOX[byte]);
            }
        }
    }

    T
}
