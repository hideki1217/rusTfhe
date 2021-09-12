#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(test)]
extern crate test;

pub mod macros;
pub mod math;
pub mod mem;
pub mod traits;
pub mod spqlios;


#[cfg(test)]
mod tests {
    
    #[test]
    fn playground() {
        let s = "12345".chars();
        let b = s.eq(['1','2']);
        let x = 2;
    }
}
