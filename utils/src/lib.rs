#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(test)]
extern crate test;
extern crate rustfft;
extern crate lazy_static;

pub mod macros;
pub mod math;
pub mod mem;
pub mod traits;


#[cfg(test)]
mod tests {
    
    #[test]
    fn playground() {
        let s = "12345".chars();
        let b = s.eq(['1','2']);
        let x = 2;
    }
}
