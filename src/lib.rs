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



pub use aead::{self, Tag, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, array::Array, inout::InOutBuf, consts::{U1, U8, U12, U16}, Buffer};
use aead::TagPosition;


#[cfg(feature = "zeroize")]
pub use zeroize;


mod grain_core;
mod fsr;
mod utils;
mod traits;
mod test_utils;

use grain_core::GrainCore;

#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Grain128 {
    pub(crate) key: u128,
}


// Implement to define key/iv size 
impl KeySizeUser for Grain128{
    type KeySize = U16;
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
    type NonceSize = U12;
    type TagSize = U8;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}


impl Grain128 {
    pub fn encrypt_aead(&self, nonce: &Nonce<Self>, associated_data: &[u8], plaintext: &[u8]) -> (Vec<u8>, Tag<Self>){
        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        let (ct, tag) = cipher.encrypt_aead(associated_data, plaintext);

        (ct, Tag::<Self>::from(tag))
    }

    pub fn decrypt_aead(&self, nonce: &Nonce<Self>, associated_data: &[u8], ciphertext: &[u8], expected_tag: &Tag<Self>) -> Result<Vec<u8>, Error> {
        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        cipher.decrypt_aead(associated_data, ciphertext, expected_tag.as_slice())
    }
}

impl AeadInOut for Grain128 {
    #[inline(always)]
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {

        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        let tag = Tag::<Self>::from(cipher.encrypt_auth_aead_inout(associated_data, buffer));

        return Ok(tag);
    }

    #[inline(always)]
    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {

        let mut nonce_int: u128 = 0;
        for i in 0..nonce.len() {
            nonce_int |= (nonce[i] as u128) << (i * 8);
        }

        let mut cipher = GrainCore::new(self.key, nonce_int);

        cipher.decrypt_auth_aead_inout(associated_data, buffer, tag.as_slice())

    }
}