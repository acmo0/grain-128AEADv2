//#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]



#[macro_use]
extern crate alloc;

pub use cipher;

use cipher::{
    BlockSizeUser, IvSizeUser,
    consts::{U1, U8, U12, U16}
};


pub use aead::{self, Tag, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, array::Array, inout::InOutBuf};
use aead::TagPosition;


#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};


mod grain_core;
mod fsr;
mod utils;
mod traits;

use grain_core::GrainCore;

struct Grain128 {
    pub(crate) key: u128,
}


// Implement to define key/iv size 
impl KeySizeUser for Grain128{
    type KeySize = U16;
}

impl IvSizeUser for Grain128 {
    type IvSize = U12;
}

impl BlockSizeUser for Grain128 {
    type BlockSize = U1;
}

impl KeyInit for Grain128 {
    fn new(key: &Key<Self>) -> Self {

        let mut key_int: u128 = 0;
        for i in 0..key.len() {
            key_int |= (key[i] as u128) << (i * 8);
        }

        Grain128 { key: key_int}
    }
}

impl AeadCore for Grain128 {
    type NonceSize = U8;
    type TagSize = U8;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}



impl AeadInOut for Grain128 {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {

        let mut cipher = GrainCore::new_with_key(self.key);

        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        cipher.init_with_iv(nonce_int);

        let tag = cipher.encrypt_auth_aead_inout(associated_data, buffer);

        Ok(Array::from(tag))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {

        let mut cipher = GrainCore::new_with_key(self.key);

        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        cipher.init_with_iv(nonce_int);

        cipher.decrypt_auth_aead_inout(associated_data, buffer, tag.as_slice())

    }
}

#[cfg(test)]
mod tests {
    use super::fsr::{
        GrainLfsr,
        GrainNfsr,
        GrainAuthRegister,
        GrainAuthAccumulator,
    };

    use super::traits::{
        Xfsr,
        Accumulator,
    };

/*    #[test]
    fn it_works() {
        let mut glfsr = GrainLfsr::new(123612162141);

        for _i in 0..1 {
            <GrainLfsr as Xfsr<u8>>::clock(&mut glfsr);
        }
    }*/
    

/*    #[test]
    fn test_acc() {
        let mut acc = GrainAuthRegister::new();
        let mut glfsr = GrainLfsr::new(123612162141);

        for _k in 0..100000000 {
            acc.accumulate(&<GrainLfsr as Xfsr<u8>>::clock(&mut glfsr));
        }
    }*/
}
