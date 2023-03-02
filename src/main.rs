use std::io::{self, BufWriter, Read, Write};

mod aes;

fn main() -> io::Result<()> {
    let mut buf = Vec::new();
    let mut key = [0u8; 16];

    // Read the first 16 bytes as the key
    std::io::stdin().read_exact(&mut key)?;

    // Key expansion
    let round_keys: [u32; 44] = aes::key_expansion(&key);

    // Read the rest of the input stream and add padding
    std::io::stdin().read_to_end(&mut buf)?;
    let rem = buf.len() % 16;
    if rem != 0 {
        for _ in 0..16 - rem {
            buf.push(0x0);
        }
    }

    assert!(buf.len() % 16 == 0);

    // Break up the incoming bytes into chunks of 16 bytes (128 bits).
    // For each chunk, run the AES algorithm and buffer the output
    let chnks: Vec<&[u8]> = buf.chunks_exact(16).collect();
    let sout = std::io::stdout().lock();
    let mut bufout = BufWriter::with_capacity(buf.len(), sout);
    let encryptor: aes::AES = aes::AES::new(round_keys);
    for c in chnks {
        bufout.write(&(encryptor.encrypt)(&encryptor, &c)).unwrap();
    }

    Ok(())
}
