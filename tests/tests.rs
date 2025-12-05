use grain_128::Grain128;
use grain_128::aead::AeadInPlace;
use grain_128::KeyInit;
use grain_128::aead::{Buffer, arrayvec::ArrayVec};

fn to_test_vector(test_vec: u128, size: usize) -> u128{
    let mut output = 0u128;

    for i in 0..size {
        let byte = (test_vec >> i * 8) & 0xff;
        
        output += byte << ((size -1)* 8 - (i * 8));
    }

    output
}

#[test]
fn test_encrypt() {
    // Init and load keys into the cipher
    let key = [0u8; 16];
    let nonce = [0u8; 12];

    let mut buffer:ArrayVec<u8, 128> = ArrayVec::new();
    buffer.extend([0, 1, 2, 3, 4, 5, 6, 7]);

    let mut cipher = Grain128::new(&key.into());
    
    cipher.encrypt_in_place(&nonce.into(), b"", &mut buffer).expect("Unable to encrypt");
    cipher.decrypt_in_place(&nonce.into(), b"", &mut buffer).expect("Unable to decrypt");
}

#[test]
fn test_encrypt_test_vectors() {
    // First set of pt/ad test vectors
    let tag = 0x7137d5998c2de4a5u128;
    // Init and load keys into the cipher
    let key = [0u8; 16];
    let nonce = [0u8; 12];

    let mut buffer:ArrayVec<u8, 128> = ArrayVec::new();
    //buffer.extend([0, 1, 2, 3, 4, 5, 6, 7]);

    let mut cipher = Grain128::new(&key.into());
    

    cipher.encrypt_in_place(&nonce.into(), b"", &mut buffer).expect("Unable to encrypt");

    assert_eq!(tag, to_test_vector(u64::from_le_bytes(buffer[..8].try_into().expect("Unable to get the tag")) as u128, 8));

    // First set of pt/ad test vectors
    let tag = 0x22b0c12039a20e28u128;
    let ct = 0x96d1bda7ae11f0bau128;
    // Init and load keys into the cipher
    let key:[u8; 16] = core::array::from_fn(|i| i as u8);
    let nonce:[u8; 12] = core::array::from_fn(|i| i as u8);;
    let ad: [u8; 8] = core::array::from_fn(|i| i as u8);
    let mut buffer:ArrayVec<u8, 128> = ArrayVec::new();
    buffer.extend([0, 1, 2, 3, 4, 5, 6, 7]);

    let mut cipher = Grain128::new(&key.into());    
    cipher.encrypt_in_place(&nonce.into(), &ad, &mut buffer).expect("Unable to encrypt");

    
    let computed_ct = to_test_vector(u64::from_le_bytes(buffer[..8].try_into().expect("Unable to get the tag")) as u128, 8);
    let computed_tag = to_test_vector(u64::from_le_bytes(buffer[8..].try_into().expect("Unable to get the tag")) as u128, 8);

    assert_eq!(tag, computed_tag);
    assert_eq!(ct, computed_ct);
}


#[test]
#[should_panic(expected = "Unable to decrypt")]
fn test_encrypt_bad_ct() {

    // Init and load keys into the cipher
    let key = [0u8; 16];
    let nonce = [0u8; 12];

    let mut buffer:ArrayVec<u8, 128> = ArrayVec::new();
    buffer.extend([0, 1, 2, 3, 4, 5, 6, 7]);

    let mut cipher = Grain128::new(&key.into());
    
    cipher.encrypt_in_place(&nonce.into(), b"", &mut buffer).expect("Unable to encrypt");
    buffer[0] = 0;
    cipher.decrypt_in_place(&nonce.into(), b"", &mut buffer).expect("Unable to decrypt");
}

#[test]
#[should_panic(expected = "Unable to decrypt")]
fn test_encrypt_bad_tag() {

    // Init and load keys into the cipher
    let key = [0u8; 16];
    let nonce = [0u8; 12];

    let mut buffer:ArrayVec<u8, 128> = ArrayVec::new();
    buffer.extend([0, 1, 2, 3, 4, 5, 6, 7]);

    let mut cipher = Grain128::new(&key.into());
    
    cipher.encrypt_in_place(&nonce.into(), b"", &mut buffer).expect("Unable to encrypt");
    buffer[10] = 0;
    cipher.decrypt_in_place(&nonce.into(), b"", &mut buffer).expect("Unable to decrypt");
}