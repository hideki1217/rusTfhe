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
    
    
    #[test]
    fn playground() {
        let b = super::math::Binary::One;
        let f:f64 = b.into(); 
        println!("{}",f);
    }
}
