use crate::utils::{
    get_ith_bit,
    get_byte_at_bit,
    get_2bytes_at_bit,
};

use crate::traits::{
    Xfsr,
    Accumulator,
};


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


/// Clock eight bits at once to speed up 
/// keystream & authentication stream generation.
impl Xfsr<u8> for GrainLfsr {
    fn get_state(&self) -> u128 {
        self.state
    }

    fn set_state(&mut self, new_value: u128) {
        self.state = new_value;
    }
    /// Update the grain's LFSR state according to the spec :
    /// - compute s' = s0 + s7 + s38 + s70 + s81 + s96
    /// - set the new state : s127 = s'
    /// - riht shift the remaining bits by one 
    /// (i.e s126 = s127, ..., s0 = s1)
    /// **The update is done on 8 bits directly (i.e 8 clocks)**
    fn feedback_function(&self) -> u128 {
        (get_byte_at_bit(&self.state, 0) ^
            get_byte_at_bit(&self.state, 7) ^
            get_byte_at_bit(&self.state, 38) ^
            get_byte_at_bit(&self.state, 70) ^
            get_byte_at_bit(&self.state, 81) ^
            get_byte_at_bit(&self.state, 96)) as u128
    }
}

/// Clock sixteen bits at once to speed up 
/// keystream & authentication stream generation.
impl Xfsr<u16> for GrainLfsr {
    fn get_state(&self) -> u128 {
        self.state
    }

    fn set_state(&mut self, new_value: u128) {
        self.state = new_value;
    }
    /// Update the grain's LFSR state according to the spec :
    /// - compute s' = s0 + s7 + s38 + s70 + s81 + s96
    /// - set the new state : s127 = s'
    /// - riht shift the remaining bits by one 
    /// (i.e s126 = s127, ..., s0 = s1)
    /// **The update is done on 16 bits directly (i.e 16 clocks)
    fn feedback_function(&self) -> u128 {
        (get_2bytes_at_bit(&self.state, 0) ^
            get_2bytes_at_bit(&self.state, 7) ^
            get_2bytes_at_bit(&self.state, 38) ^
            get_2bytes_at_bit(&self.state, 70) ^
            get_2bytes_at_bit(&self.state, 81) ^
            get_2bytes_at_bit(&self.state, 96)) as u128
    }
}


/// Core structure for the Grain128-AEADv2 NFSR
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

    pub fn xor_last_byte(&mut self, byte: u8) -> () {
        self.state ^= (byte as u128) << 120;
    }

    pub fn xor_last_2bytes(&mut self, bytes: u16) -> () {
        self.state ^= (bytes as u128) << 112;
    }

}


impl Xfsr<u8> for GrainNfsr {
    fn get_state(&self) -> u128 {
        self.state
    }

    fn set_state(&mut self, new_value: u128) {
        self.state = new_value;
    }
    /// Update the grain's NFSR state accord to the spec
    /// EXCEPT that the feedback bit is not xored with
    /// the bit from the grain LFSR output
    fn feedback_function(&self) -> u128 {
        let output = (get_byte_at_bit(&self.state, 0) ^
            get_byte_at_bit(&self.state, 26) ^
            get_byte_at_bit(&self.state, 56) ^
            get_byte_at_bit(&self.state, 91) ^
            get_byte_at_bit(&self.state, 96) ^
            get_byte_at_bit(&self.state, 3) & get_byte_at_bit(&self.state, 67) ^
            get_byte_at_bit(&self.state, 11) & get_byte_at_bit(&self.state, 13) ^
            get_byte_at_bit(&self.state, 17) & get_byte_at_bit(&self.state, 18) ^
            get_byte_at_bit(&self.state, 27) & get_byte_at_bit(&self.state, 59) ^
            get_byte_at_bit(&self.state, 40) & get_byte_at_bit(&self.state, 48) ^
            get_byte_at_bit(&self.state, 61) & get_byte_at_bit(&self.state, 65) ^
            get_byte_at_bit(&self.state, 68) & get_byte_at_bit(&self.state, 84) ^
            (
                get_byte_at_bit(&self.state, 22) &
                get_byte_at_bit(&self.state, 24) &
                get_byte_at_bit(&self.state, 25)
            ) ^
            (
                get_byte_at_bit(&self.state, 70) &
                get_byte_at_bit(&self.state, 78) &
                get_byte_at_bit(&self.state, 82)
            ) ^
            (
                get_byte_at_bit(&self.state, 88) &
                get_byte_at_bit(&self.state, 92) &
                get_byte_at_bit(&self.state, 93) &
                get_byte_at_bit(&self.state, 95)
            )) as u128;

        debug_assert!(output < (1u128 << 8));

        output
    }

}

impl Xfsr<u16> for GrainNfsr {
    fn get_state(&self) -> u128 {
        self.state
    }

    fn set_state(&mut self, new_value: u128) {
        self.state = new_value;
    }
    /// Update the grain's NFSR state accord to the spec
    /// EXCEPT that the feedback bit is not xored with
    /// the bit from the grain LFSR output
    fn feedback_function(&self) -> u128 {
        let output = (get_2bytes_at_bit(&self.state, 0) ^
            get_2bytes_at_bit(&self.state, 26) ^
            get_2bytes_at_bit(&self.state, 56) ^
            get_2bytes_at_bit(&self.state, 91) ^
            get_2bytes_at_bit(&self.state, 96) ^
            get_2bytes_at_bit(&self.state, 3) & get_2bytes_at_bit(&self.state, 67) ^
            get_2bytes_at_bit(&self.state, 11) & get_2bytes_at_bit(&self.state, 13) ^
            get_2bytes_at_bit(&self.state, 17) & get_2bytes_at_bit(&self.state, 18) ^
            get_2bytes_at_bit(&self.state, 27) & get_2bytes_at_bit(&self.state, 59) ^
            get_2bytes_at_bit(&self.state, 40) & get_2bytes_at_bit(&self.state, 48) ^
            get_2bytes_at_bit(&self.state, 61) & get_2bytes_at_bit(&self.state, 65) ^
            get_2bytes_at_bit(&self.state, 68) & get_2bytes_at_bit(&self.state, 84) ^
            (
                get_2bytes_at_bit(&self.state, 22) &
                get_2bytes_at_bit(&self.state, 24) &
                get_2bytes_at_bit(&self.state, 25)
            ) ^
            (
                get_2bytes_at_bit(&self.state, 70) &
                get_2bytes_at_bit(&self.state, 78) &
                get_2bytes_at_bit(&self.state, 82)
            ) ^
            (
                get_2bytes_at_bit(&self.state, 88) &
                get_2bytes_at_bit(&self.state, 92) &
                get_2bytes_at_bit(&self.state, 93) &
                get_2bytes_at_bit(&self.state, 95)
            )) as u128;

        debug_assert!(output < (1u128 << 16));
        output
    }

}


pub struct GrainAuthAccumulator {
    pub(crate) state: u64,
}


impl Accumulator<u8> for GrainAuthAccumulator {
    fn accumulate(&mut self, new: &u8) -> u8 {
        let output = get_ith_bit(&self.state, 63);
        self.state <<= 1;
        self.state |= *new as u64;

        output
    }

/*    fn accumulate_u8(&mut self, new: &u8) -> u8 {
        let output = ((self.state >> 56) & 0xff) as u8;
        self.state <<= 8;
        self.state |= *new as u64;

        output
    }

    fn accumulate_u16(&mut self, new: &u16) -> u16 {
        let output = ((self.state >> 48) & 0xff) as u16;
        self.state <<= 16;
        self.state |= *new as u64;

        output
    }
*/
   fn new() -> GrainAuthAccumulator { 
       GrainAuthAccumulator { state: 0u64 } 
   }
}


pub struct GrainAuthRegister {
    pub(crate) state: u64,
}

impl Accumulator<u8> for GrainAuthRegister {
    fn accumulate(&mut self, new: &u8) -> u8 {
        let output = self.state & 1;
        self.state >>= 1;
        self.state |= (*new as u64) << 63;

        output as u8
    }

/*    fn accumulate_u8(&mut self, new: &u8) -> u8 {
        let output = ((self.state >> 56) & 0xff) as u8;
        self.state <<= 8;
        self.state |= *new as u64;

        output
    }

    fn accumulate_u16(&mut self, new: &u16) -> u16 {
        let output = ((self.state >> 48) & 0xff) as u16;
        self.state <<= 16;
        self.state |= *new as u64;

        output
    }*/

    fn new() -> GrainAuthRegister {
        GrainAuthRegister { state: 0u64 }
    }
}


#[cfg(test)]
mod tests { 
    use super::*;

    
    const TEST_NFSR: u128 = 0x008040c020a060e0109050d030b070f0;
    const TEST_LFSR: u128 = 0x008040c020a060e0109050d0fffffffe;
    const TEST_ACC: u64 = 0xe34e40ce5ee7e377;
    const TEST_REG: u64 = 0xcc48b6eb45d809ce;

    
}