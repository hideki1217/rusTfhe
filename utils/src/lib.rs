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
        let val = -0.25_f32;
        let mut val = (val - val.floor()).fract();
        let u = unsafe { *(&mut val as *mut _ as *mut u32) };
        println!("u={:32b}",u);
        let exp = 127 - ((u & 0b0_11111111_00000000000000000000000_u32) >> 23);// 指数部
        let x = u & 0b0_00000000_11111111111111111111111_u32/*仮数部*/;
        println!("x={:32b}",x);
        let x = x + (1<<23);
        println!("x={:32b}",x);
        let x = x << (32 - 23 - exp);
        println!("x={:32b}",x);
        println!("d={}",Decimal::from_bits(x));

        let val = 0.5_f64;
        let mut val = (val - val.floor()).fract();
        let u = unsafe { *(&mut val as *mut _ as *mut u64) };
        let exp = 1023 - ((u & 0b0_11111111111_0000000000_0000000000_0000000000_0000000000_0000000000_00_u64) >> 52);// 指数部
        let x = (((u & 0b0_00000000000_1111111111_1111111111_1111111111_1111111111_1111111111_11_u64)/*仮数部*/ + 1<<52) >> (52 - 32 + exp)) as u32; 
        let d = Decimal::from_bits(x);
        println!("val={},d={}",val,d);
    }
}
