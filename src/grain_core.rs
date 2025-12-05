extern crate alloc;
use alloc::vec::Vec;

use aead::{
    Error,
    inout::InOutBuf
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
};


pub(crate) struct GrainCore {
    lfsr: GrainLfsr,
    nfsr: GrainNfsr,
    auth_accumulator: GrainAuthAccumulator,
    auth_register: GrainAuthRegister,
}

impl GrainCore {

    pub fn new(key: u128, iv: u128) -> Self {

        if iv >= (1u128 << 96) {
            panic!("Unable to init Grain-128AEADv2, IV is too big (must be 12 bytes)");
        }

        let mut cipher = GrainCore {
            lfsr: GrainLfsr::new((0x7fffffff << 96) | iv),
            nfsr: GrainNfsr::new(key),
            auth_accumulator: GrainAuthAccumulator::new(),
            auth_register: GrainAuthRegister::new(),
        };




        // Clock 320 times and re-input the feedback to both LFSR and NFSR
        for _i in 0..20 {
            let fb: u128 = cipher.clock_u16() as u128;
            cipher.lfsr.state ^= fb << 112;
            cipher.nfsr.state ^= fb << 112;
        }
        
        // Clock 64 times and re-input the feedback to both LFSR and NFSR
        // + re-introduce key
        for i in 0..4 {
            let fb: u128 = cipher.clock_u16() as u128;
            cipher.lfsr.state ^= (fb ^ (key >> (i * 16 + 64)) & 0xffff as u128) << 112;
            cipher.nfsr.state ^= (fb ^ (key >> (i * 16)) & 0xffff as u128) << 112;
            
        }
        
        // Init the accumulator/register
        let mut acc_state: u64 = 0;
        for i in 0..4 {
            let fb: u64 = cipher.clock_u16() as u64;
            
            acc_state |= fb << i * 16
        }
        cipher.auth_accumulator.state = acc_state;

        

        let mut reg_state: u64 = 0;
        for i in 0..4 {
            let fb: u64 = cipher.clock_u16() as u64;
            
            reg_state |= fb << i * 16
        }
        cipher.auth_register.state = reg_state;

        cipher
    }

    pub fn clock_u16(&mut self) -> u16 {
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

        let lfsr_output: u16 = self.lfsr.clock();
        let nfsr_output: u16 = self.nfsr.clock();

        self.nfsr.xor_last_2bytes(lfsr_output);

        output
    }

    fn update_auth_accumulator(&mut self) {
        self.auth_accumulator.state ^= self.auth_register.state;
    }

    fn encrypt_and_auth_byte(&mut self, data: &u8) -> u8 {
        let keystream = self.clock_u16();

        // Extract keystream (at even indexes)
        let encrypt_stream = {
            let mut byte = 0u8;
            for i in 0..8 {
                byte |= (((keystream >> (i << 1)) & 1) << i) as u8; 
            }
            byte
        };

        let auth_stream = {
            let mut byte = 0u8;
            for i in 0..8 {
                byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
            }
            byte
        };

        self.auth_byte(&auth_stream, &data);

        data ^ encrypt_stream
        
    }

    fn decrypt_and_auth_byte(&mut self, data: &u8) -> u8 {
        let keystream = self.clock_u16();

        // Extract keystream (at even indexes)
        let encrypt_stream = {
            let mut byte = 0u8;
            for i in 0..8 {
                byte |= (((keystream >> (i << 1)) & 1) << i) as u8; 
            }
            byte
        };

        let auth_stream = {
            let mut byte = 0u8;
            for i in 0..8 {
                byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
            }
            byte
        };

        let output = data ^ encrypt_stream;

        self.auth_byte(&auth_stream, &output);

        output
        
    }


    fn auth_byte(&mut self, auth_stream: &u8, data: &u8) {
        // Update the auth register
        for i in 0..8 {
            if (data >> i) & 1 == 1u8 {
                self.update_auth_accumulator()
            }
            self.auth_register.accumulate(&(((auth_stream >> i) & 1) as u8));

        }
    }

    pub fn encrypt_auth(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(data.len() + 1);

        for b in data {
            output.push(self.encrypt_and_auth_byte(&b));
        }

        // Add padding + encrypt/auth
        self.encrypt_and_auth_byte(&1u8);

        output
    }

    pub fn decrypt_auth(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(data.len() + 1);

        for b in data {
            output.push(self.encrypt_and_auth_byte(&b));
        }

        // Add padding + encrypt/auth
        self.decrypt_and_auth_byte(&1u8);

        output
    }

    pub fn encrypt_auth_aead(&mut self, authenticated_data: &[u8], data: &[u8]) -> (Vec<u8>, [u8; 8]) {
        // Init the output with the associated data encoded length
        let encoded_len = {
            if authenticated_data.len() == 0 {
                vec![0]
            } else {
                utils::len_encode(authenticated_data.len())

            }
        };
        let mut output: Vec<u8> = Vec::with_capacity(authenticated_data.len() + data.len() + 9);

        // Auth data
        for b in encoded_len {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        // Auth data
        for b in authenticated_data {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        output.extend(self.encrypt_auth(data));

        (output, self.auth_accumulator.state.to_le_bytes())
    }

    pub fn decrypt_aead(&mut self, authenticated_data: &[u8], data: &[u8], tag: &[u8]) -> Result<Vec<u8>, Error> {
        // Init the output with the associated data encoded length
        let encoded_len = {
            if authenticated_data.len() == 0 {
                vec![0]
            } else {
                utils::len_encode(authenticated_data.len())

            }
        };
        let output: Vec<u8> = Vec::with_capacity(authenticated_data.len() + data.len() + 9);

        // Auth data
        for b in encoded_len {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        // Auth data
        for b in authenticated_data {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        let output = self.decrypt_auth(data);

        if self.auth_accumulator.state.to_le_bytes().as_slice() != tag {
            return Err(Error);
        }

        Ok(output)
    }

    pub fn encrypt_auth_aead_inout(&mut self, authenticated_data: &[u8], mut data: InOutBuf<'_, '_, u8>,) -> [u8; 8] {
        let tag: [u8; 8] = [0u8; 8];

        // Init the output with the associated data encoded length
        let encoded_len = {
            if authenticated_data.len() == 0 {
                vec![0]
            } else {
                utils::len_encode(authenticated_data.len())

            }
        };

        // Auth data
        for b in encoded_len {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        // Auth data
        for b in authenticated_data {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        
        for i in 0..data.len() {
            let encrypted_byte = self.encrypt_and_auth_byte(&data.get_in()[i]);
            data.get_out()[i..(i+1)].copy_from_slice(&[encrypted_byte]);
        }

        // Add padding + encrypt/auth
        self.encrypt_and_auth_byte(&1u8);
        
        self.auth_accumulator.state.to_le_bytes()
    }

    pub fn decrypt_auth_aead_inout(&mut self, authenticated_data: &[u8], mut data: InOutBuf<'_, '_, u8>, tag: &[u8]) -> Result<(), Error> {

        // Init the output with the associated data encoded length
        let encoded_len = {
            if authenticated_data.len() == 0 {
                vec![0]
            } else {
                utils::len_encode(authenticated_data.len())

            }
        };

        // Auth data
        for b in encoded_len {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        // Auth data
        for b in authenticated_data {
            let keystream = self.clock_u16();
            let auth_stream = {
                let mut byte = 0u8;
                for i in 0..8 {
                    byte |= (((keystream >> (1 | i << 1)) & 1) << i) as u8; 
                }
                byte
            };

            self.auth_byte(&auth_stream, &b);
        }

        
        for i in 0..data.len() {
            let decrypted_byte = self.decrypt_and_auth_byte(&data.get_in()[i]);

            data.get_out()[i..(i+1)].copy_from_slice(&[decrypted_byte]);
        }
        // Add padding + encrypt/auth
        self.encrypt_and_auth_byte(&1u8);
        
        
        if tag != self.auth_accumulator.state.to_le_bytes().as_slice() {
            return Err(Error);
        } else {
            return Ok(());
        }
    }
}


#[cfg(test)]
mod tests { 
    use super::*;

    use proptest::prelude::*;
    
    fn to_test_vector(test_vec: u128, size: usize) -> u128{
        let mut output = 0u128;

        for i in 0..size {
            let byte = (test_vec >> i * 8) & 0xff;
            
            output += byte << ((size -1)* 8 - (i * 8));
        }

        output
    }

    #[test]
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
        
        cipher.encrypt_auth_aead(&[], &[]);
        assert_eq!(tag, to_test_vector(cipher.auth_accumulator.state.into(), 8));

    }

    #[test]
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


        let (encrypted, tag) = cipher.encrypt_auth_aead(&ad, &pt);


        let ct: [u8; 8] = encrypted.try_into().unwrap();
        
        assert_eq!(enc_state, to_test_vector(u64::from_le_bytes(ct) as u128, 8));
        assert_eq!(tag_state, to_test_vector(u64::from_le_bytes(tag) as u128, 8));
        
    }

}

