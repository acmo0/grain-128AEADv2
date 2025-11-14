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
