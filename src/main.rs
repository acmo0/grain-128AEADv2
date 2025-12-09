use grain_128::{
    Grain128, Key, Nonce,
    aead::{AeadCore, AeadInOut, KeyInit}
};


const KB: usize = 1024;

fn main() {
    let key = Grain128::generate_key().expect("Unable to generate key");
    let cipher = Grain128::new(&key);

    // A nonce must be USED ONLY ONCE !
    let nonce = Grain128::generate_nonce().expect("Unable to generate nonce");
    // Take care : 8 bytes overhead to store the tag
    let mut buffer: Vec<u8> = vec![0u8; KB];
    buffer.extend_from_slice(b"a secret message");
    
    for i in 0..100 {
    // Perform in place encryption inside 'buffer'
        cipher.encrypt_in_place(&nonce, b"Some AD", &mut buffer).expect("Unable to encrypt");
    }

    assert_ne!(&buffer, b"a secret message");
}