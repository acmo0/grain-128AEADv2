use num::traits::{Unsigned, One, ToPrimitive};
use core::ops::{
    BitAnd,
    Shr,
};
use core::cmp::PartialEq;

/// Returns the i-th bit of an unsigned integer
pub fn get_ith_bit<T: Unsigned + BitAnd<Output = T> + One + ToPrimitive>(value: &T, index: usize) -> u8
where 
    for<'a> &'a T: Shr<usize, Output = T> 
{
    ((value >> index) & T::one()).to_u8().expect("Unable extract the given bit index")
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

    use rand::prelude::*;
    use num::traits::{Unsigned, One, ToPrimitive};
    use core::fmt::Debug;
    extern crate std;

    #[test]
    fn test_get_ith_bit_u8() {
        for i in 0..=255u8 { 
            for k in 0..8 {
                assert_eq!(get_ith_bit(&i, k), ((i >> k) & 1) as u8);
            }
        }
    }
   
   // #[test]
   // fn test_get_ith_bit_u16() {  
   //     for _i in 0..NTRIES {
   //         let random: u16 = rand::random(); 
   //         let index: usize = rand::random_range(0..16) as usize;

   //         assert_eq!(get_ith_bit(&random, index), ((random >> index) & 1) as u8);
   //     }
   // }

   // #[test]
   // fn test_get_ith_bit_u32() {  
   //     for _i in 0..NTRIES {
   //         let random: u32 = rand::random(); 
   //         let index: usize = rand::random_range(0..32) as usize;

   //         assert_eq!(get_ith_bit(&random, index), ((random >> index) & 1) as u8);
   //     }
   // }

   // #[test]
   // fn test_get_ith_bit_u64() {  
   //     for _i in 0..NTRIES {
   //         let random: u64 = rand::random(); 
   //         let index: usize = rand::random_range(0..64) as usize;

   //         assert_eq!(get_ith_bit(&random, index), ((random >> index) & 1) as u8);
   //     }
   // }

   // #[test]
   // fn test_get_ith_bit_u128() {  
   //     for _i in 0..NTRIES {
   //         let random: u128 = rand::random(); 
   //         let index: usize = rand::random_range(0..128) as usize;

   //         assert_eq!(get_ith_bit(&random, index), ((random >> index) & 1) as u8);
   //     }
   // }

}
