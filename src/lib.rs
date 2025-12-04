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
    AlgorithmName, Block, BlockSizeUser, Iv, IvSizeUser, KeyIvInit,
    ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure, StreamCipherCore,
    StreamCipherCoreWrapper,
    consts::{U1, U8, U12, U16}
};

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser};
use aead::{TagPosition, inout::InOutBuf};


#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};


mod grain_core;
mod fsr;
mod utils;
mod traits;

use grain_core::GrainCore;

pub type Grain128 = StreamCipherCoreWrapper<GrainCore>;


// Implement to define key/iv size 
impl KeySizeUser for GrainCore{
    type KeySize = U16;
}

impl IvSizeUser for GrainCore {
    type IvSize = U12;
}

impl BlockSizeUser for GrainCore {
    type BlockSize = U1;
}

impl KeyInit for GrainCore {
    fn new(key: &Key<Self>) -> Self {

        let mut key_int: u128 = 0;
        for i in 0..key.len() {
            key_int |= (key[i] as u128) << (i * 8);
        }

        GrainCore::new_with_key(key_int)
    }
}

impl AeadCore for GrainCore {
    type NonceSize = U8;
    type TagSize = U8;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}
/*
impl AeadInOut {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag, Error> {
        Cipher::<Aes>::new(&self.key_generating_key, nonce)
            .encrypt_inout_detached(associated_data, buffer)
    }
}*/

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
