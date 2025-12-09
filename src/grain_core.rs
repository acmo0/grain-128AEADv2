#[cfg(feature = "vec")]
use alloc::vec::Vec;

use aead::{
    Error,
    inout::InOutBuf,
    consts::U2,
};

use crate::fsr::{
   GrainLfsr,
   GrainNfsr,
   GrainAuthAccumulator,
   GrainAuthRegister,
};

use crate::traits::{
    Xfsr,
    Accumulator,
};

use crate::utils::{
    self,
    get_2bytes_at_bit,
    get_4bytes_at_bit
};

pub(crate) struct GrainCore {
    lfsr: GrainLfsr,
    nfsr: GrainNfsr,
    auth_accumulator: GrainAuthAccumulator,
    auth_register: GrainAuthRegister,
}

impl GrainCore {

    /// Init a new instance of Grain-128AEADv2 as specified 
    /// in the NIST spec in Section 2.2.
    pub(crate) fn new(key: u128, iv: u128) -> Self {
        // Ensure that the size of the IV doesn't exceed 12 bytes.
        if iv >= (1u128 << 96) {
            panic!("Unable to init Grain-128AEADv2, IV is too big (must be 12 bytes)");
        }

        // Init/load the keys into grain cipher
        let mut cipher = GrainCore {
            lfsr: GrainLfsr::new((0x7fffffff << 96) | iv),
            nfsr: GrainNfsr::new(key),
            auth_accumulator: GrainAuthAccumulator::new(),
            auth_register: GrainAuthRegister::new(),
        };


        // Clock 320 times and re-input the feedback to both LFSR and NFSR
        for _i in 0..10 {
            let fb: u128 = cipher.clock_u32() as u128;
            cipher.lfsr.state ^= fb << 96;
            cipher.nfsr.state ^= fb << 96;
        }
        
        // Clock 64 times and re-input the feedback to both LFSR and NFSR
        // + re-introduce key
        for i in [0, 32] {
            let fb = cipher.clock_u32();
            cipher.lfsr.state ^= ((fb ^ get_4bytes_at_bit(&key, i + 64)) as u128) << 96;
            cipher.nfsr.state ^= ((fb ^ get_4bytes_at_bit(&key, i)) as u128) << 96;
        }
        
        // Init the accumulator
        let fb1 = cipher.clock_u32() as u64;
        let fb2 = cipher.clock_u32() as u64;
        cipher.auth_accumulator.state = (fb2 << 32) | fb1;

        // Init the register
        let fb1 = cipher.clock_u32() as u64;
        let fb2 = cipher.clock_u32() as u64;
        cipher.auth_register.state = (fb2 << 32) | fb1;

        cipher
    }


    /* 
        #########################################################
        # Code related to clocking the cipher (by 2 ou 4 bytes) #
        #########################################################
    */
    /// Clock 16 times at once the cipher to optimize software
    /// implementation because we're working at byte-level. This
    /// returns the pre-output according to NIST spec. in Section 2.1
    fn clock_u16(&mut self) -> u16 {
        // Get the 9 bytes from LFSR/NFSR and compute the
        // "pre-output" as defined in grain-128AEADv2 spec
        let x0 = get_2bytes_at_bit(&self.nfsr.state, 12);
        let x1 = get_2bytes_at_bit(&self.lfsr.state, 8);
        let x2 = get_2bytes_at_bit(&self.lfsr.state, 13);
        let x3 = get_2bytes_at_bit(&self.lfsr.state, 20);
        let x4 = get_2bytes_at_bit(&self.nfsr.state, 95);
        let x5 = get_2bytes_at_bit(&self.lfsr.state, 42);
        let x6 = get_2bytes_at_bit(&self.lfsr.state, 60);
        let x7 = get_2bytes_at_bit(&self.lfsr.state, 79);
        let x8 = get_2bytes_at_bit(&self.lfsr.state, 94);
        

        let output = (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8) ^
            get_2bytes_at_bit(&self.lfsr.state, 93) ^
            get_2bytes_at_bit(&self.nfsr.state, 2)  ^
            get_2bytes_at_bit(&self.nfsr.state, 15) ^
            get_2bytes_at_bit(&self.nfsr.state, 36) ^
            get_2bytes_at_bit(&self.nfsr.state, 45) ^
            get_2bytes_at_bit(&self.nfsr.state, 64) ^
            get_2bytes_at_bit(&self.nfsr.state, 73) ^
            get_2bytes_at_bit(&self.nfsr.state, 89);

        // Clock/update the xFSRs
        let lfsr_output: u16 = self.lfsr.clock();
        let _: u16 =  self.nfsr.clock();
        self.nfsr.xor_last_2bytes(lfsr_output);

        output
    }

    /// Clock 32 times at once the cipher to optimize software
    /// implementation because we're working at byte-level. This
    /// returns the pre-output according to NIST spec. in Section 2.1
    fn clock_u32(&mut self) -> u32 {
        // Get the 9 bytes from LFSR/NFSR and compute the
        // "pre-output" as defined in grain-128AEADv2 spec
        let x0 = get_4bytes_at_bit(&self.nfsr.state, 12);
        let x1 = get_4bytes_at_bit(&self.lfsr.state, 8);
        let x2 = get_4bytes_at_bit(&self.lfsr.state, 13);
        let x3 = get_4bytes_at_bit(&self.lfsr.state, 20);
        let x4 = get_4bytes_at_bit(&self.nfsr.state, 95);
        let x5 = get_4bytes_at_bit(&self.lfsr.state, 42);
        let x6 = get_4bytes_at_bit(&self.lfsr.state, 60);
        let x7 = get_4bytes_at_bit(&self.lfsr.state, 79);
        let x8 = get_4bytes_at_bit(&self.lfsr.state, 94);
        

        let output = (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8) ^
            get_4bytes_at_bit(&self.lfsr.state, 93) ^
            get_4bytes_at_bit(&self.nfsr.state, 2)  ^
            get_4bytes_at_bit(&self.nfsr.state, 15) ^
            get_4bytes_at_bit(&self.nfsr.state, 36) ^
            get_4bytes_at_bit(&self.nfsr.state, 45) ^
            get_4bytes_at_bit(&self.nfsr.state, 64) ^
            get_4bytes_at_bit(&self.nfsr.state, 73) ^
            get_4bytes_at_bit(&self.nfsr.state, 89);

        // Clock/update the xFSRs
        let lfsr_output: u32 = self.lfsr.clock();
        let _: u32 = self.nfsr.clock();
        self.nfsr.xor_last_4bytes(lfsr_output);

        output
    }

    /// Update grain-128AEADv2 accumulator according to
    /// NIST spec. in Section 2.3
    #[inline(always)]
    fn update_auth_accumulator(&mut self) {
        self.auth_accumulator.state ^= self.auth_register.state;
    }


    /*
        ###############################################################
        # Code related to encryption/authentication stream generation #
        ###############################################################
    */
    /// Clock 32 times the cipher and extract the streams for
    /// authentication and encryption/decryption according to
    /// NIST spec. in Section 2.3.
    #[inline(always)]
    fn get_stream16(&mut self) -> (u16, u16){
        let keystream = self.clock_u32();
        utils::deinterleave32(&keystream)
    }

    /// Clock 16 times the cipher and extract the streams for
    /// authentication and encryption/decryption according to
    /// NIST spec. in Section 2.3.
    #[inline(always)]
    fn get_stream8(&mut self) -> (u8, u8){
        let keystream = self.clock_u16();
        utils::deinterleave16(&keystream)
    }


    /*
        ##################################
        # Code related to authentication #
        ##################################
    */
    /// Authenticate a single byte of plaintext according to
    /// NIST spec. in Section 2.3.
    fn auth_2bytes(&mut self, auth_stream: &u16, data: &[u8]) {
        // Update the auth register
        for i in 0..2 {
            for j in 0..8 {
                if (data[i] >> j) & 1 == 1u8 {
                    self.update_auth_accumulator()
                }
                self.auth_register.accumulate(((auth_stream >> ((i << 3) + j)) & 1) as u8);
            }
        }
    }

    /// Authenticate additionnal data according 
    /// to Grain-128AEADv2 spec. in Section 2.5
    fn auth_additionnal_data(&mut self, authenticated_data: &[u8]) {
        // Init the output with the associated data encoded length
        let encoded_len = {
            if authenticated_data.is_empty() {
                vec![0]
            } else {
                utils::len_encode(authenticated_data.len())

            }
        };

        // Authenticate the additionnal data len representation
        let (blocks, last_block) = encoded_len.as_chunks::<2>();
        
        for block in blocks {
            let (_, auth_stream) = self.get_stream16();
            self.auth_2bytes(&auth_stream, block);
        }
        
        if !last_block.is_empty() {
            let (_, auth_stream) = self.get_stream8();
            self.auth_byte(&auth_stream, &last_block[0]);
        }

        
        // Authenticate additionnal data
        let (blocks, last_block) = authenticated_data.as_chunks::<2>();
        
        for block in blocks {
            let (_, auth_stream) = self.get_stream16();
            self.auth_2bytes(&auth_stream, block);
        }
        
        if !last_block.is_empty() {
            let (_, auth_stream) = self.get_stream8();
            self.auth_byte(&auth_stream, &last_block[0]);
        }
    }


    /*
        #####################################################################
        # Code related to encryption/decryption/authentication by 1/2 bytes #
        #####################################################################
    */
    /// Perform the encryption and authentication of 2 bytes
    /// of data according to NIST spec. in Section 2.3.
    fn encrypt_and_auth_2bytes(&mut self, data: &[u8]) -> [u8; 2] {
        let (encrypt_stream, auth_stream) = self.get_stream16();

        // Auth the plaintext byte
        self.auth_2bytes(&auth_stream, data);

        // Encrypt the plaintext
        [data[0] ^ ((encrypt_stream & 0xff) as u8), data[1] ^ ((encrypt_stream >> 8) as u8)]
        
    }

    /// Perform the decryption and authentication of 2 bytes
    /// of data according to NIST spec. in Section 2.3.
    fn decrypt_and_auth_2bytes(&mut self, data: &[u8]) -> [u8; 2] {
        let (encrypt_stream, auth_stream) = self.get_stream16();

        let output = [
            data[0] ^ ((encrypt_stream & 0xff) as u8),
            data[1] ^ ((encrypt_stream >> 8) as u8)
        ];

        // Auth the plaintext byte
        self.auth_2bytes(&auth_stream, &output);

        output
        
    }

    /// Perform the encryption and authentication of a single
    /// byte of data according to NIST spec. in Section 2.3.
    fn encrypt_and_auth_byte(&mut self, data: &u8) -> u8 {
        let (encrypt_stream, auth_stream) = self.get_stream8();
        self.auth_byte(&auth_stream, data);

        data ^ encrypt_stream
        
    }

    /// Perform the decryption and authentication of a single
    /// byte of data according to NIST spec. in Section 2.3.
    fn decrypt_and_auth_byte(&mut self, data: &u8) -> u8 {
        let (encrypt_stream, auth_stream) = self.get_stream8();

        let output = data ^ encrypt_stream;

        self.auth_byte(&auth_stream, &output);

        output
        
    }

    /// Authenticate a single byte of plaintext according to
    /// NIST spec. in Section 2.3.
    fn auth_byte(&mut self, auth_stream: &u8, data: &u8) {
        // Update the auth register
        for i in 0..8 {
            if (data >> i) & 1 == 1u8 {
                self.update_auth_accumulator()
            }
            self.auth_register.accumulate((auth_stream >> i) & 1);

        }
    }


    /*
        #################################################################
        # Public functions to encrypt/decrypt without RustCrypto traits #
        #################################################################
    */
    /// Encrypts and authenticate a given plaintext, and (potential) additionnal
    /// authenticated data according to the NIST spec. in Section 2.6.1. It returns
    /// the ciphertext and the authentication tag.
    #[cfg(feature = "vec")]
    pub(crate) fn encrypt_aead(&mut self, authenticated_data: &[u8], data: &[u8]) -> (Vec<u8>, [u8; 8]) {
        let mut output: Vec<u8> = Vec::with_capacity(data.len());

        // Auth additionnal data
        self.auth_additionnal_data(authenticated_data);
    
        // Split plaintext by block of two bytes and encrypt it
        let (blocks, last_block) = data.as_chunks::<2>();

        for block in blocks {
            output.extend(self.encrypt_and_auth_2bytes(block))
        }

        // Potentially encrypt the last byte + add padding
        if !last_block.is_empty() {
            output.push(self.encrypt_and_auth_2bytes(&[last_block[0], 1u8])[0]);
        } else {
            // Add padding + encrypt/auth
            self.encrypt_and_auth_byte(&1u8);
        }

        (output, self.auth_accumulator.state.to_le_bytes())
    }


    /// Decrypts and authenticate a given ciphertext, and (potential) additionnal
    /// authenticated data according to the NIST spec. in Section 2.6.1.
    /// It returns the plaintext if the given tag is correct, otherwise it fails.
    #[cfg(feature = "vec")]
    pub(crate) fn decrypt_aead(&mut self, authenticated_data: &[u8], data: &[u8], tag: &[u8]) -> Result<Vec<u8>, Error> {
        let mut output: Vec<u8> = Vec::with_capacity(data.len());

        // Authenticate data
        self.auth_additionnal_data(authenticated_data);

        let (blocks, last_block) = data.as_chunks::<2>();

        for block in blocks {
            output.extend(self.decrypt_and_auth_2bytes(block));
        }

        if !last_block.is_empty() {
            output.push(self.decrypt_and_auth_byte(&last_block[0]));
        }

        // Add padding + encrypt/auth
        self.encrypt_and_auth_byte(&1u8);

        if self.auth_accumulator.state.to_le_bytes().as_slice() != tag {
            return Err(Error);
        }

        Ok(output)
    }

    /*
        ##############################################################
        # Public functions to encrypt/decrypt with RustCrypto traits #
        ##############################################################
    */
    /// Encrypts and authenticate a given plaintext, and (potential) additionnal
    /// authenticated data according to the NIST spec. in Section 2.6.1. The
    /// encryption is done in-place to match the RustCrypto traits requirements.
    /// It returns only the tag since the encrypted data is stored in the data
    /// buffer.
    pub(crate) fn encrypt_auth_aead_inout(&mut self, authenticated_data: &[u8], data: InOutBuf<'_, '_, u8>,) -> [u8; 8] {

        self.auth_additionnal_data(authenticated_data);
        
        let (blocks, mut last_block) = data.into_chunks::<U2>();

        for mut block in blocks {
            let encrypted = self.encrypt_and_auth_2bytes(block.get_in());
            block.get_out().copy_from_slice(&encrypted);
        }

        if !last_block.is_empty() {
            let encrypted_byte = self.encrypt_and_auth_2bytes(&[last_block.get_in()[0], 1u8])[0];
            last_block.get_out()[0..1].copy_from_slice(&[encrypted_byte]);
        } else {
            // Add padding + encrypt/auth
            self.encrypt_and_auth_byte(&1u8);
        }
        
        self.auth_accumulator.state.to_le_bytes()
    }

    /// Decrypts and authenticate a given ciphertext, and (potential) additionnal
    /// authenticated data according to the NIST spec. in Section 2.6.1. The
    /// decryption is done in-place to match the RustCrypto traits requirements.
    /// It fails if the given tag doesn't match the computed tag.
    pub(crate) fn decrypt_auth_aead_inout(&mut self, authenticated_data: &[u8], data: InOutBuf<'_, '_, u8>, tag: &[u8]) -> Result<(), Error> {

        self.auth_additionnal_data(authenticated_data);
        
        let (blocks, mut last_block) = data.into_chunks::<U2>();

        for mut block in blocks {
            let decrypted = self.decrypt_and_auth_2bytes(block.get_in());
            block.get_out().copy_from_slice(&decrypted);
        }

        if !last_block.is_empty() {
            let decrypted_byte = self.decrypt_and_auth_byte(&last_block.get_in()[0]);
            last_block.get_out()[0..1].copy_from_slice(&[decrypted_byte]);
        }

        // Add padding + encrypt/auth
        self.encrypt_and_auth_byte(&1u8);
        
        if tag != self.auth_accumulator.state.to_le_bytes().as_slice() {
            Err(Error)
        } else {
            Ok(())
        }
    }
}


#[cfg(test)]
mod tests { 
    use super::*;
    use crate::test_utils::to_test_vector;
    use proptest::prelude::*;
    

    // Performs an initialization and an encryption
    // of an all-zero key/nonce with an empty plaintext.
    // It checks the LFSR/NFSR/Accumulator/Register states
    // and the computed tag according the the tests
    // vectors given in the NIST spec. in Section 7. 
    #[test]
    #[cfg(feature = "vec")]
    fn test_load_null() {
        // Test vectors from Grain-128AEADv2 spec
        let lfsr_state = 0x8f395a9421b0963364e2ed30679c8ee1u128;
        let nfsr_state = 0x81f7e0c655d035823310c278438dbc20u128;
        let acc_state = 0xe89a32b9c0461a6au128;
        let reg_state = 0xb199ade7204c6bfeu128;
        let tag = 0x7137d5998c2de4a5u128;

        // Init and load keys into the cipher
        let mut cipher = GrainCore::new(0, 0);
        
        assert_eq!(nfsr_state, to_test_vector(cipher.nfsr.state, 16));
        assert_eq!(lfsr_state, to_test_vector(cipher.lfsr.state, 16));
        assert_eq!(acc_state, to_test_vector(cipher.auth_accumulator.state.into(), 8));
        assert_eq!(reg_state, to_test_vector(cipher.auth_register.state.into(), 8));
        
        cipher.encrypt_aead(&[], &[]);
        assert_eq!(tag, to_test_vector(cipher.auth_accumulator.state.into(), 8));

    }


    // Performs an initialization and an encryption
    // of given key/nonce/plaintext/auth data set
    // It checks the LFSR/NFSR/Accumulator/Register states
    // and the computed ciphertext/tag according the the tests
    // vectors given in the NIST spec. in Section 7. 
    #[test]
    #[cfg(feature = "vec")]
    fn test_load_non_null() {
        // Test vectors from Grain-128AEADv2 spec
        let nfsr_state = 0xb3c2e1b1eec1f08c2d6eae957f6af9d0u128;
        let lfsr_state = 0x0e1f950d45e05087c4cd63fd00eab310u128;
        let acc_state = 0xc77202737ae7c7eeu128;
        let reg_state = 0x33126dd7a21b9073u128;
        let enc_state = 0x96d1bda7ae11f0bau128;
        let tag_state = 0x22b0c12039a20e28u128;

        // Plaintext / authenticated data from test vectors
        let ad = (0x0001020304050607u64).to_be_bytes();
        let pt = (0x0001020304050607u64).to_be_bytes();

        // Init and load keys into the cipher
        let mut cipher = GrainCore::new(
            to_test_vector(0x000102030405060708090a0b0c0d0e0fu128, 16),
            to_test_vector(0x000102030405060708090a0bu128, 12)
        );
        
        assert_eq!(nfsr_state, to_test_vector(cipher.nfsr.state, 16));
        assert_eq!(lfsr_state, to_test_vector(cipher.lfsr.state, 16));
        assert_eq!(acc_state, to_test_vector(cipher.auth_accumulator.state.into(), 8));
        assert_eq!(reg_state, to_test_vector(cipher.auth_register.state.into(), 8));


        let (encrypted, tag) = cipher.encrypt_aead(&ad, &pt);


        let ct: [u8; 8] = encrypted.try_into().unwrap();
        
        assert_eq!(enc_state, to_test_vector(u64::from_le_bytes(ct) as u128, 8));
        assert_eq!(tag_state, to_test_vector(u64::from_le_bytes(tag) as u128, 8));
        
    }

    // Tries to init, encrypt and decrypt without any modification
    // of the ciphertext. It checks then that we indeed retrieve
    // the right decrypted plaintext.
    #[test]
    #[cfg(feature = "vec")]
    fn test_encrypt_decrypt() {
        // Plaintext / authenticated data from test vectors
        let ad = (0x0001020304050607u64).to_be_bytes();
        let pt = (0x0001020304050607u64).to_be_bytes();

        // Init and load keys into the cipher
        let mut cipher = GrainCore::new(
            0, 0
        );
        
        let (encrypted, tag) = cipher.encrypt_aead(&ad, &pt);

        // Init and load keys into the cipher
        cipher = GrainCore::new(
            0, 0
        );

        let decrypted = cipher.decrypt_aead(&ad, &encrypted, &tag).expect("Unable to decrypt");

        assert_eq!(decrypted, pt);
    }

    // Tries to init, encrypt and decrypt but while modifying
    // the ciphertext. This should fail because the tag is
    // no longer valid.
    #[test]
    #[should_panic(expected = "Unable to decrypt")]
    #[cfg(feature = "vec")]
    fn test_encrypt_decrypt_wrong_ct() {
        // Plaintext / authenticated data from test vectors
        let ad = (0x0001020304050607u64).to_be_bytes();
        let pt = (0x0001020304050607u64).to_be_bytes();

        // Init and load keys into the cipher
        let mut cipher = GrainCore::new(
            0, 0
        );
        
        let (mut encrypted, tag) = cipher.encrypt_aead(&ad, &pt);

        // Init and load keys into the cipher
        cipher = GrainCore::new(
            0, 0
        );

        encrypted[0] = 0;

        let decrypted = cipher.decrypt_aead(&ad, &encrypted, &tag).expect("Unable to decrypt");

        assert_eq!(decrypted, pt);
    }

    // Tries to init, encrypt and decrypt but while modifying
    // the tag. It should fail because the tag is not valid
    // anymore.
    #[test]
    #[should_panic(expected = "Unable to decrypt")]
    #[cfg(feature = "vec")]
    fn test_encrypt_decrypt_wrong_ad() {
        // Plaintext / authenticated data from test vectors
        let ad = (0x0001020304050607u64).to_be_bytes();
        let ad2 = (0x0101020304050607u64).to_be_bytes();
        let pt = (0x0001020304050607u64).to_be_bytes();

        // Init and load keys into the cipher
        let mut cipher = GrainCore::new(
            0, 0
        );
        
        let (encrypted, tag) = cipher.encrypt_aead(&ad, &pt);

        // Init and load keys into the cipher
        cipher = GrainCore::new(
            0, 0
        );

        let decrypted = cipher.decrypt_aead(&ad2, &encrypted, &tag).expect("Unable to decrypt");

        assert_eq!(decrypted, pt);
    }


    // Tries to init a new Grain128-AEADv2 cipher with an
    // nonce that is too big acc. to the specs
    proptest! {
        #[test]
        #[should_panic(expected = "Unable to init Grain-128AEADv2, IV is too big (must be 12 bytes)")]
        fn test_init_too_big(iv in (1 << 96)..(u128::MAX)) {
            GrainCore::new(0, iv);
        }
    }
}

