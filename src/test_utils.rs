#![cfg(test)]
pub(crate) fn to_test_vector(test_vec: u128, size: usize) -> u128{
    let mut output = 0u128;

    for i in 0..size {
        let byte = (test_vec >> i * 8) & 0xff;
        
        output += byte << ((size -1)* 8 - (i * 8));
    }

    output
}