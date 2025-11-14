use num::traits::{Unsigned, One, ToPrimitive, FromPrimitive};
use core::ops::{
    BitAnd,
    Shr,
};
use core::cmp::PartialEq;

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

/// Evaluate a multivariate polynomial over F2^n for n less or equals to 128.
///
/// For a polynomial that is defined as $P(x_1, \ldots, x_n) = \sum_j\prod_i x_i$
/// we represent the $\prod_i x_i$ with the integer where the (i-1)-th bit is set to 1
/// if and only if $x_i$ appears in the product. Each product of the sum should be
/// added in an array.
///
/// # Example
///
/// Let say you want to evaluate $P(x_1, \ldots, x_4) = x_1 + x_4 + x_2x_3 + x_1x_2x_3x_4$ :
///
/// ```rust
/// let poly: [u8; 4] = [
///     0b00000001,
///     0b00001000,
///     0b00000110,
///     0b00001111
/// ];
///
/// let p2 = evaluate_poly(poly, 2u8);
/// ```
pub fn evaluate_poly<T: PartialEq, const N: usize>(polynomial: [T; N], value: &T) -> u8
where
    for<'a, 'b> &'a T: BitAnd<&'b T, Output=T>
{
    let mut output: u8 = 0;

    for monomial in polynomial.iter() {
        if &(monomial & value) == monomial {
            output ^= 1u8;
        }
    }

    output
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
    // Tests for `evaluate_poly` function
    // ********************************
    // Define a macro to generate a test function based on proptest module
    // to perform unit/property tests of evaluate_poly.
    macro_rules! test_evaluate_poly_for {
        ($name:tt, $type: ty) => {
            proptest! {
                #[test]
                fn $name(poly in 0..(<$type>::MAX - 1), value in 0..(<$type>::MAX - 1)) {
                    std::println!("{:?}", &value);
                    // This evaluation should always equals zero bc value < 0xff...ff
                    assert_eq!(evaluate_poly([<$type>::MAX], &value), 0u8);

                    // this equals the parity of the low 8 bits
                    assert_eq!(
                        evaluate_poly([1, 2, 4, 8, 16, 32, 64, 128], &value),
                        ((value & 0xff).count_ones() % 2) as u8
                    );

                    assert_eq!(evaluate_poly([poly], &value), ((poly & value) == poly )as u8);
                }
            }
        }
    }

    test_evaluate_poly_for!(test_evaluate_poly_u8, u8);
    test_evaluate_poly_for!(test_evaluate_poly_u16, u16);
    test_evaluate_poly_for!(test_evaluate_poly_u32, u32);
    test_evaluate_poly_for!(test_evaluate_poly_u64, u64);
    test_evaluate_poly_for!(test_evaluate_poly_u128, u128);

}
