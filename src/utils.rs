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


        let mut encoded = vec![0x80u8 + (size_len as u8)];
        for i in size_len..lenght_bytes.len() {
            encoded.push(lenght_bytes[i])
        }
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

}
