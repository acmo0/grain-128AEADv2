#![feature(test)]

#[cfg(test)]
mod benches {

    
    use super::fsr::*;
    extern crate std;
    extern crate test;
    use test::Bencher;
    use rand;

    #[bench]
    fn bench_lfsr(bencher: &mut Bencher) { 
        let mut glfsr = GrainLfsr::new(rand::random());
        
        bencher.iter(|| std::hint::black_box(glfsr.clock()));
    }

    #[bench]
    fn bench_nfsr(bencher: &mut Bencher) {
        let mut gnfsr = GrainNfsr::new(rand::random());

        bencher.iter(|| std::hint::black_box(gnfsr.clock()));
    }

    #[bench]
    fn test_acc(bencher: &mut Bencher) {
        let mut acc = GrainAuthRegister::new();
        let to_acc: u8 = rand::random();


        bencher.iter(|| std::hint::black_box(acc.accumulate(to_acc)));
    }
}