#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(test)]
extern crate test;
extern crate debug_print;
extern crate itertools;
extern  crate threadpool;

extern crate utils;

pub mod digest;
pub mod tlwe;
pub mod trgsw;
pub mod trlwe;
pub mod tfhe;


#[cfg(test)]
mod tests {

    use num::ToPrimitive;
    use utils::math::Decimal;

    use super::*;

    #[test]
    fn experiment() {
        let x = 0x8180_0000_u32;
        println!("{:b}",x);
        let x_ = x + (1 << (32 - 8 - 1));
        println!("{:b}",x_);
        println!("{:b}",x >> (32 -8 -1));
        let d = Decimal::from_bits(0x8180_0000_u32);
        println!("{}",d);
        let x = (d.inner() + (1 << (32 - 8 - 1))) >> (32 - 8);
        println!("{}",x);
        let y = d.to_f32().unwrap()*2.0_f32.powi(8);
        println!("{}",y);
        println!("{}",d.inner() >> (32 - 8));
    }
}
