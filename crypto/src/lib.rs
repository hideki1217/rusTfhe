#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(test)]
extern crate test;
extern crate debug_print;

extern crate utils;

pub mod digest;
pub mod tlwe;
pub mod trgsw;
pub mod trlwe;

pub fn add_two(a: i32) -> i32 {
    a + 2
}
#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[test]
    fn experiment() {
        println!("{}",trlwe::TRLWEHelper::ALPHA);
    }

    #[bench]
    fn bench_add_two(b: &mut Bencher) {
        b.iter(|| add_two(2));
    }
}
