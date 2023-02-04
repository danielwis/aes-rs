mod aes;

fn main() {
    println!("AES Implementation coming up...");

    // Run the key expansion algorithm and save the round keys

    // Break up the incoming bytes into chunks of 16 bytes (128 bits).
    // For each chunk, run the AES algorithm
    aes::substitute_bytes();
}
