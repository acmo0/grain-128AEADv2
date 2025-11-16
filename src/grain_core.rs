use crate::fsr::{
   GrainLfsr,
   GrainNfsr,
   GrainAuthAccumulator,
   GrainAuthRegister,
};

use crate::traits::{
    Xfsr,
    Accumulator,
};

use crate::utils::{
    get_ith_bit,
    evaluate_poly,
    get_byte_at_bit,
    get_2bytes_at_bit,
};


struct GrainCore {
    lfsr: GrainLfsr,
    nfsr: GrainNfsr,
    auth_accumulator: GrainAuthAccumulator,
    auth_register: GrainAuthRegister,
}


impl GrainCore {
    pub fn clock_u8(&mut self) -> u8 {
        let lfsr_output: u8 = self.lfsr.clock();
        let nfsr_output: u8 = self.nfsr.clock();

        self.nfsr.xor_last_byte(lfsr_output);

        let x0 = get_byte_at_bit(&self.nfsr.state, 12);
        let x1 = get_byte_at_bit(&self.lfsr.state, 8);
        let x2 = get_byte_at_bit(&self.lfsr.state, 13);
        let x3 = get_byte_at_bit(&self.lfsr.state, 20);
        let x4 = get_byte_at_bit(&self.nfsr.state, 95);
        let x5 = get_byte_at_bit(&self.lfsr.state, 42);
        let x6 = get_byte_at_bit(&self.lfsr.state, 60);
        let x7 = get_byte_at_bit(&self.lfsr.state, 79);
        let x8 = get_byte_at_bit(&self.lfsr.state, 94);
        

        x0 & x1 ^ x2 & x3 ^ x4 & x5 ^ x6 & x7 ^ x0 & x4 & x8 ^
            get_byte_at_bit(&self.lfsr.state, 93) ^
            get_byte_at_bit(&self.nfsr.state, 2)  ^
            get_byte_at_bit(&self.nfsr.state, 15) ^
            get_byte_at_bit(&self.nfsr.state, 36) ^
            get_byte_at_bit(&self.nfsr.state, 45) ^
            get_byte_at_bit(&self.nfsr.state, 64) ^
            get_byte_at_bit(&self.nfsr.state, 73) ^
            get_byte_at_bit(&self.nfsr.state, 89)
    }

    pub fn clock_u16(&mut self) -> u16 {
        let lfsr_output: u16 = self.lfsr.clock();
        let nfsr_output: u16 = self.nfsr.clock();

        self.nfsr.xor_last_2bytes(lfsr_output);

        let x0 = get_2bytes_at_bit(&self.nfsr.state, 12);
        let x1 = get_2bytes_at_bit(&self.lfsr.state, 8);
        let x2 = get_2bytes_at_bit(&self.lfsr.state, 13);
        let x3 = get_2bytes_at_bit(&self.lfsr.state, 20);
        let x4 = get_2bytes_at_bit(&self.nfsr.state, 95);
        let x5 = get_2bytes_at_bit(&self.lfsr.state, 42);
        let x6 = get_2bytes_at_bit(&self.lfsr.state, 60);
        let x7 = get_2bytes_at_bit(&self.lfsr.state, 79);
        let x8 = get_2bytes_at_bit(&self.lfsr.state, 94);
        

        x0 & x1 ^ x2 & x3 ^ x4 & x5 ^ x6 & x7 ^ x0 & x4 & x8 ^
            get_2bytes_at_bit(&self.lfsr.state, 93) ^
            get_2bytes_at_bit(&self.nfsr.state, 2)  ^
            get_2bytes_at_bit(&self.nfsr.state, 15) ^
            get_2bytes_at_bit(&self.nfsr.state, 36) ^
            get_2bytes_at_bit(&self.nfsr.state, 45) ^
            get_2bytes_at_bit(&self.nfsr.state, 64) ^
            get_2bytes_at_bit(&self.nfsr.state, 73) ^
            get_2bytes_at_bit(&self.nfsr.state, 89)
    }
}