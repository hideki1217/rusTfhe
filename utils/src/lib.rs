#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(test)]
extern crate test;
extern crate rustfft;
extern crate lazy_static;

pub mod macros;
pub mod math;
pub mod mem;


#[cfg(test)]
mod tests {
    use crate::math::Decimal;

    
    
    #[test]
    fn playground() {
        let u = 0x8000_0000_u32;
        let f_u = (u as f32) / ((u32::MAX)as f32);
        let f = 0.5_f32;
        let u_f = (f * 2.0_f32.powi(32)) as u32;
        let x = 1.5;
        let y = x%1.0;
        let x = 1;
    }
}
