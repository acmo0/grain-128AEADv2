use num::traits::{Unsigned, One, ToPrimitive, FromPrimitive};
use core::ops::{
    BitAnd,
    Shr,
};
use alloc::vec::Vec;

/// Returns the i-th bit of an unsigned integer. Mostly useful to bootstrap/make more comprehensive code.
pub fn get_ith_bit<T: Unsigned + BitAnd<Output = T> + One + ToPrimitive>(value: &T, index: usize) -> u8
where 
    for<'a> &'a T: Shr<usize, Output = T> 
{
    ((value >> index) & T::one()).to_u8().expect("Unable extract the given bit index")
}


/// Extract the next 8 bits starting from a given position.
pub fn get_byte_at_bit<T: Unsigned + BitAnd<Output = T> + One + ToPrimitive + FromPrimitive>(value: &T, index: usize) -> u8
where 
    for<'a> &'a T: Shr<usize, Output = T> 
{
    (
        (value >> index) & T::from_u8(0xff).expect("Unable to get the given byte")
    ).to_u8()
     .expect("Unable extract the given byte index")
}

/// Extract the next 16 bits starting from a given position.

pub fn get_2bytes_at_bit<T: Unsigned + BitAnd<Output = T> + One + ToPrimitive + FromPrimitive>(value: &T, index: usize) -> u16
where 
    for<'a> &'a T: Shr<usize, Output = T> 
{
    (
        (value >> index) & T::from_u16(0xffff).expect("Unable to get the given byte")
    ).to_u16()
     .expect("Unable extract the given byte index")
}


pub fn get_4bytes_at_bit<T: Unsigned + BitAnd<Output = T> + One + ToPrimitive + FromPrimitive>(value: &T, index: usize) -> u32
where 
    for<'a> &'a T: Shr<usize, Output = T> 
{
    (
        (value >> index) & T::from_u32(0xffffffff).expect("Unable to get the given byte")
    ).to_u32()
     .expect("Unable extract the given byte index")
}


pub fn deinterleave32(input: &u32) -> (u16, u16) {

    let input = *input as u64;
    let mut output = (((input) << 31) | input) & 0x5555555555555555;
    output = (output | (output >> 1)) & 0x3333333333333333;
    output = (output | (output >> 2)) & 0x0f0f0f0f0f0f0f0f;
    output = (output | (output >> 4)) & 0x00ff00ff00ff00ff;
    output = output | (output >> 8);

    (
        (output & 0xffff) as u16,
        (output >> 32) as u16
    )
}

pub fn deinterleave16(input: &u16) -> (u8, u8) {

    let input = *input as u32;
    let mut output = (((input) << 15) | input) & 0x55555555;
    output = (output | (output >> 1)) & 0x33333333;
    output = (output | (output >> 2)) & 0x0f0f0f0f;
    output = output | (output >> 4);
    
    (
        (output & 0xff) as u8,
        (output >> 16) as u8
    )
}

/// Encode a length according to Grain spec
pub fn len_encode(length: usize) -> Vec<u8> {
    if length <= 127 {
        vec![length as u8]
    } else {
        let lenght_bytes = length.to_be_bytes();
        let mut size_len = 0usize;

        while lenght_bytes[size_len] == 0 {
            size_len += 1
        }

        let mut encoded = vec![0x80u8 + ((8 - size_len) as u8)];
        encoded.extend_from_slice(&lenght_bytes[size_len..]);

        encoded
    }
}



#[cfg(test)]
mod tests { 
    use super::*;

    use proptest::prelude::*;
    
    extern crate std;
    use std::mem;

    // ********************************
    // Tests for `get_ith_bit` function
    // ********************************
    // We can test every values for u8 and u16 to assert that
    // our function get_ith_bit is working well. We can't do
    // the same for "bigger" types (e.g u32, .., u128).
    #[test]
    fn test_get_ith_bit_u8() {
        for i in 0..=255u8 { 
            for k in 0..8 {
                assert_eq!(get_ith_bit(&i, k), ((i >> k) & 1) as u8);
            }
        }
    }
   
    #[test]
    fn test_get_ith_bit_u16() {  
        for i in 0..=65533u16 {
            for k in 0..16 {
                assert_eq!(get_ith_bit(&i, k), ((i >> k) & 1) as u8);
            }
        }
    }

    // Define a macro to generate a test function base on proptest module
    // to perform unit/property tests on u32, ..., u128. 
    macro_rules! test_get_ith_bit_function_for {
        ($name:tt, $type: ty) => {
            proptest! {
                #[test]
                fn $name(i in any::<$type>(), k in 0..(mem::size_of::<$type>())) {
                    assert_eq!(get_ith_bit(&i, k), ((i >> k) & 1) as u8);
                }
            }
        }
    }

    // Use the previous defined macro to generate the tests for u32, ..., u128
    test_get_ith_bit_function_for!(test_get_ith_bit_u32, u32);
    test_get_ith_bit_function_for!(test_get_ith_bit_u64, u64);
    test_get_ith_bit_function_for!(test_get_ith_bit_u128, u128);
    

    // ********************************
    // Tests for `get_byte_at_bit` function
    // ********************************
    // Define a macro to generate a test function based on proptest module
    // to perform unit/property tests of evaluate_poly.
    macro_rules! test_get_byte_at_bit_for {
        ($name:tt, $type: ty) => {
            proptest! {
                #[test]
                fn $name(value in 0..(<$type>::MAX), pos in 0..(mem::size_of::<$type>())) {
                    assert_eq!(get_byte_at_bit(&value, pos), ((value >> pos) & 0xff) as u8);
                }
            }
        }
    }

    test_get_byte_at_bit_for!(test_get_byte_at_bit_u8, u8);
    test_get_byte_at_bit_for!(test_get_byte_at_bit_u16, u16);
    test_get_byte_at_bit_for!(test_get_byte_at_bit_u32, u32);
    test_get_byte_at_bit_for!(test_get_byte_at_bit_u64, u64);
    test_get_byte_at_bit_for!(test_get_byte_at_bit_u128, u128);


    // ********************************
    // Tests for `get_2bytes_at_bit` function
    // ********************************
    // Define a macro to generate a test function based on proptest module
    // to perform unit/property tests of evaluate_poly.
    macro_rules! test_get_2bytes_at_bit_for {
        ($name:tt, $type: ty) => {
            proptest! {
                #[test]
                fn $name(value in 0..(<$type>::MAX), pos in 0..(mem::size_of::<$type>())) {
                    assert_eq!(get_2bytes_at_bit(&value, pos), ((value >> pos) & 0xffff) as u16);
                }
            }
        }
    }

    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u16, u16);
    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u32, u32);
    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u64, u64);
    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u128, u128);


    proptest! {
        #[test]
        fn test_len_encode_le_127(l in 0..=127usize) {
            assert_eq!(len_encode(l), vec![l as u8]);
        }        
    }

    proptest! {
        #[test]
        fn test_len_encode_ge_127(l in 128..4294967296usize) {
            let encoded = len_encode(l);
            
            // Ensure first bit is set to 1
            assert_eq!((encoded[0] >> 7) & 1, 1);
            
            // Ensure the remaining first byte bits encode
            // the byte length of the size
            assert_eq!(encoded[0] & 0x7f, l.to_be_bytes().into_iter().skip_while(|&x| x == 0).count() as u8);

            // Ensure the remaining bytes represents the len
            let encoded_size: usize = {
                let mut s = 0;
                for i in 1..(encoded.len()) {
                    s += (encoded[i] as usize) << (encoded.len() - i - 1) * 8
                }
                s
            };
            assert_eq!(encoded_size, l);
        }
    }
}
