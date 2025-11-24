use num::{PrimInt};
use core::ops::BitAnd;


/// Trait that both LFSR and NFSR will implement
///
/// This trait provide a method to apply a feedback function
/// to the xFSR state and a clock method to clock once the xFSR
pub trait Xfsr<T: PrimInt> {
    #[inline(always)]
    fn get_state(&self) -> u128;

    #[inline(always)]
    fn set_state(&mut self, new_value: u128);
    
    #[inline(always)]
    fn feedback_function(&self) -> u128;
    
    fn clock(&mut self) -> T {
        let size = (T::max_value()).count_ones() as usize;
        let mask = (1 << size) - 1;

        let state = self.get_state();

        let output = T::from(&state & mask).expect("Unable to clock xFSR");

        self.set_state(
            (state >> size) | (self.feedback_function() << (128 - size))
        );

        output
    }
}


pub trait Accumulator<T> {
    fn accumulate(&mut self, new: &T) -> T;
    fn accumulate_u8(&mut self, new: &u8) -> u8;
    fn accumulate_u16(&mut self, new: &u16) -> u16;
    fn new() -> Self;
}
