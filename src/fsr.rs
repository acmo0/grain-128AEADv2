use crate::utils::{
    get_ith_bit,
    evaluate_poly
};

const GRAIN_NFSR_FB_POLY: [u128; 15] = [
    0x00000000000000000000000000000001,
    0x00000000000000000000000004000000,
    0x00000000000000000100000000000000,
    0x00000000080000000000000000000000,
    0x00000001000000000000000000000000,
    0x00000000000000080000000000000008,
    0x00000000000000000000000000002800,
    0x00000000000000000000000000060000,
    0x00000000000000000800000008000000,
    0x00000000000000000001010000000000,
    0x00000000000000022000000000000000,
    0x00000000001000100000000000000000,
    0x00000000000000000000000003400000,
    0x00000000000440400000000000000000,
    0x00000000b10000000000000000000000,
];

/// Trait that both LFSR and NFSR will implement
///
/// This trait provide a method to apply a feedback function
/// to the xFSR state and a clock method to clock once the xFSR
pub trait Xfsr<T> {
    fn feedback_function(&mut self) -> T;
    fn clock(&mut self) -> T;
}

pub trait Accumulator<T> {
    fn accumulate(&mut self, new: &T) -> T;
    fn new() -> Self;
}


/// Core structure of the 128bits grain LFSR
pub struct GrainLfsr {
    pub(crate) state: u128,
}


impl GrainLfsr {
    /// Return a new Grain LFSR initialized with the given state
    pub fn new(initial_state: u128) -> GrainLfsr {
        GrainLfsr {
            state: initial_state,
        }
    }
}


impl Xfsr<u8> for GrainLfsr {
    /// Update the grain's LFSR state according to the spec :
    /// - compute s' = s0 + s7 + s38 + s70 + s81 + s96
    /// - set the new state : s127 = s'
    /// - riht shift the remaining bits by one 
    /// (i.e s126 = s127, ..., s0 = s1)
    fn feedback_function(&mut self) -> u8 {
        let mut s: u8 = get_ith_bit(&self.state, 0);
        s ^= get_ith_bit(&self.state, 7);
        s ^= get_ith_bit(&self.state, 38);
        s ^= get_ith_bit(&self.state, 70);
        s ^ get_ith_bit(&self.state, 96)
    }

    fn clock(&mut self) -> u8 {
        let output = self.feedback_function();

        self.state = (self.state >> 1) | ((output as u128) << 127);

        output
    }
}


pub struct GrainNfsr {
    pub(crate) state: u128,
}

impl GrainNfsr {
    /// Return a new Grain LFSR initialized with the given state
    pub fn new(initial_state: u128) -> GrainNfsr {
        GrainNfsr {
            state: initial_state,
        }
    }

    pub fn xor_last_bit(&mut self, bit: u8) -> () {
        self.state ^= (bit as u128) << 127;
    }
}

impl Xfsr<u8> for GrainNfsr {
    /// Update the grain's NFSR state accord to the spec
    /// EXCEPT that the feedback bit is not xored with
    /// the bit from the grain LFSR output
    fn feedback_function(&mut self) -> u8 {
        evaluate_poly(GRAIN_NFSR_FB_POLY, &self.state)
    }

    fn clock(&mut self) -> u8 {
        let output = self.feedback_function();

        self.state = (self.state << 1) | (output as u128);

        output
    }
}


pub struct GrainAuthAccumulator {
    state: u64,
}

impl Accumulator<u8> for GrainAuthAccumulator {
    fn accumulate(&mut self, new: &u8) -> u8 {
        let output = get_ith_bit(&self.state, 63);
        self.state <<= 1 | new;

        output
    }

   fn new() -> GrainAuthAccumulator { 
       GrainAuthAccumulator { state: 0u64 } 
   }
}


pub struct GrainAuthRegister {
    state: u64,
}

impl Accumulator<u8> for GrainAuthRegister {
    fn accumulate(&mut self, new: &u8) -> u8 {
        let output = get_ith_bit(&self.state, 63);
        self.state <<= 1 | new;

        output
    }

    fn new() -> GrainAuthRegister {
        GrainAuthRegister { state: 0u64 }
    }
}


