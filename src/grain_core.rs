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

    pub fn new(key: u128, iv: u128) -> Self {

        if iv >= (1u128 << 96) {
            panic!("Unable to init Grain-128AEADv2, IV is too big (must be 24 bytes)");
        }

        let mut cipher = GrainCore {
            lfsr: GrainLfsr::new((0x7fffffffffffffff << 96) | iv),
            nfsr: GrainNfsr::new(key),
            auth_accumulator: GrainAuthAccumulator::new(),
            auth_register: GrainAuthRegister::new(),
        };

        // Clock 320 times and re-input the feedback to both LFSR and NFSR
        for _i in 0..20 {
            let fb: u128 = cipher.clock_u16() as u128;
            cipher.lfsr.state ^= fb << 112;
            cipher.nfsr.state ^= fb << 112;
        }

        // Clock 64 times and re-input the feedback to both LFSR and NFSR
        // + re-introduce key
        for i in 0..4 {
            let fb: u128 = cipher.clock_u16() as u128;
            cipher.lfsr.state ^= (fb ^ (key >> (i * 16) + 64) & 0xffff as u128) << 112;
            cipher.nfsr.state ^= (fb ^ (key >> i * 16) & 0xffff as u128) << 112;
        }

        // Init the accumulator/register
        let mut acc_state: u64 = 0;
        for i in 0..4 {
            let fb: u64 = cipher.clock_u16() as u64;
            acc_state |= fb << i * 16
        }
        cipher.auth_accumulator.state = acc_state;

        let mut reg_state: u64 = 0;
        for i in 0..4 {
            let fb: u64 = cipher.clock_u16() as u64;
            reg_state |= fb << i * 16
        }
        cipher.auth_register.state = acc_state;

        // Clock 128 times
        for _i in 0..8 {
            cipher.clock_u16();
        }

        cipher
    }

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
