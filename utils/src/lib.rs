#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(test)]
extern crate test;

pub mod macros;
pub mod math;
pub mod mem;
pub mod spqlios;
pub mod traits;

#[cfg(test)]
mod tests {

    #[test]
    fn playground() {
        let s = "12345".chars();
        let b = s.eq(['1', '2']);
        let x = 2;
        let x_ = x ^ 0xffff_ffff_u32 as i32;
        let x__ = x ^ 0xffff_fffe_u32 as i32;
        let x = 3;
        let x_ = x ^ 0xffff_ffff_u32 as i32;
        let x__ = x ^ 0xffff_fffe_u32 as i32;
        let y = 1;
    }
}
