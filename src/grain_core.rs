use crate::fsr::{
   GrainLfsr,
   GrainNfsr,
   Xfsr,
   GrainAuthAccumulator,
   GrainAuthRegister,
};
use crate::utils::{
    get_ith_bit,
    evaluate_poly
};



const GRAIN_PRE_OUT_POLYNOMIAL: [u16; 5] = [
    0b000000011,
    0b000001100,
    0b000110000,
    0b011000000,
    0b100010001,
];


struct GrainCore {
    lfsr: GrainLfsr,
    nfsr: GrainNfsr,
    auth_accumulator: GrainAuthAccumulator,
    auth_register: GrainAuthRegister,
    is_odd_bit: bool,
}


impl Xfsr<u8> for GrainCore {
    /// Update the grain's state
    /// - Update the NFSR
    /// - Update the LFSR
    /// - Apply a function on eight precise bits
    /// - Ouput the generated bit
    fn feedback_function(&mut self) -> u8 {
        
        let lfsr_output = self.lfsr.clock();
        let nfsr_output = self.nfsr.clock();

        self.nfsr.xor_last_bit(lfsr_output);

        let extracted_bits: u16 = get_ith_bit(&self.nfsr.state, 12) as u16 +
            ((get_ith_bit(&self.lfsr.state, 8) as u16) << 1) +
            ((get_ith_bit(&self.lfsr.state, 13) as u16) << 2) +
            ((get_ith_bit(&self.lfsr.state, 20) as u16) << 3) +
            ((get_ith_bit(&self.nfsr.state, 95) as u16) << 4) +
            ((get_ith_bit(&self.lfsr.state, 42) as u16) << 5) +
            ((get_ith_bit(&self.lfsr.state, 60) as u16) << 6) +
            ((get_ith_bit(&self.lfsr.state, 79) as u16) << 7) +
            ((get_ith_bit(&self.lfsr.state, 94) as u16) << 8);
        
        evaluate_poly(GRAIN_PRE_OUT_POLYNOMIAL, &extracted_bits) ^
            get_ith_bit(&self.lfsr.state, 93) ^
            get_ith_bit(&self.nfsr.state, 2) ^
            get_ith_bit(&self.nfsr.state, 15) ^
            get_ith_bit(&self.nfsr.state, 36) ^
            get_ith_bit(&self.nfsr.state, 45) ^
            get_ith_bit(&self.nfsr.state, 64) ^
            get_ith_bit(&self.nfsr.state, 73) ^
            get_ith_bit(&self.nfsr.state, 89)
    }

    fn clock(&mut self) -> u8 {
        self.feedback_function()
    }
}

//fn get_ith_bit<T: Unsigned + BitAnd>(value: &T, index: usize) -> u8 where &T: Shr<usize> {
//    ((value >> index) & 1) as u8
//}
//
//fn apply_poly<const N: usize, T: Unsigned + BitAnd + BitXor>(value: &T, poly: &[[usize; N]]) -> u8 where &T: Shr<usize> {
//    let mut output: u8 = 0;
//
//    for monomial_index in 0..len(poly) {
//        let mut evaluated_mon: u8 = 0;
//        
//        for i in 0..N {
//            evaluated_mon = evaluated_mon & get_ith_bit(value, poly[monomial_index][i]);
//        }
//
//        output = output ^ evaluated_mon;
//    }
//
//    output
//}
//
//struct State {
//    lfsr_state: u128,
//    nfsr_state: u128
//}
//
//
//impl State {
//    /// Update the grain's LFSR state according to the spec :
//    /// - compute s' = s0 + s7 + s38 + s70 + s81 + s96
//    /// - set the new state : s127 = s'
//    /// - riht shift the remaining bits by one 
//    /// (i.e s126 = s127, ..., s0 = s1)
//    fn update_lfsr(&mut self) {
//        
//        let s0: u8 = get_ith_bit(&self.lfsr_state, 0);
//        let s7: u8 = get_ith_bit(&self.lfsr_state, 7);
//        let s38: u8 = get_ith_bit(&self.lfsr_state, 38);
//        let s70: u8 = get_ith_bit(&self.lfsr_state, 70);
//        let s96: u8 = get_ith_bit(&self.lfsr_state, 96);
//        
//        let s = (s0 ^ s7 ^ s38 ^ s70 ^ s96) as u128;
//
//        self.lfsr_state  = (&self.lfsr_state >> 1) | (s << 127);
//    }
//
//    /// Update the grain's NFSR according to the spec :
//    /// - compu
//    fn update_nfsr(&mut self) {
//        let mut nfsr_update: u8 = 0;
//
//
//    }
//a
