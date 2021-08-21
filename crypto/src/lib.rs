#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(test)]
extern crate test;
extern crate debug_print;
extern crate itertools;

extern crate utils;

pub mod digest;
pub mod tlwe;
pub mod trgsw;
pub mod trlwe;
pub mod tfhe;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn experiment() {
        println!("{}",-3_i32 as u32);
    }
}
