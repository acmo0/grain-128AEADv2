#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    AlgorithmName, Block, BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser,
    ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure, StreamCipherCore,
    StreamCipherCoreWrapper,
    consts::{U12, U16},
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};





mod grain_core;
mod fsr;
mod utils;
mod traits;

#[cfg(test)]
mod tests {
    use super::fsr::{
        GrainLfsr,
        Xfsr,
        Accumulator,
        GrainNfsr,
        GrainAuthRegister,
        GrainAuthAccumulator,
    };

    #[test]
    fn it_works() {
        let mut glfsr = GrainLfsr::new(123612162141);

        for _i in 0..1 {
            glfsr.clock();
        }
    }
    
    #[test]
    fn test_acc() {
        let mut acc = GrainAuthRegister::new();
        let mut glfsr = GrainLfsr::new(123612162141);

        for _k in 0..100000000 {
            acc.accumulate(&glfsr.clock());
        }
    }
}



