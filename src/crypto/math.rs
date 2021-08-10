use std::{
    collections::btree_set::Union,
    convert,
    num::Wrapping,
    ops::{Add, Mul},
};

use num::{Float, Integer, Num, NumCast, ToPrimitive, Unsigned, traits::{Pow, WrappingAdd}};

/**
  0.5 = 101000...
  0.8 = 000100...
  Ex.  0.5 + 0.625
  = 100000.. + 10100... = 0010000... = 0.125
  Ex.  0.5 * 3
  = 100000.. * 3 = 100000.. = 0.5
*/
struct Decimal<U: Unsigned>(U);
impl<U: Unsigned + WrappingAdd> Add for Decimal<U> {
    type Output = Decimal<U>;

    fn add(self, rhs: Self) -> Self::Output {
        Decimal(self.0.wrapping_add(&rhs.0))
    }
}
impl<T: ToPrimitive> Mul<T> for Decimal<u32> {
    type Output = Decimal<u32>;

    fn mul(self, rhs: T) -> Self::Output {
        Decimal(self.0.wrapping_mul(*rhs.to_u32().get_or_insert(0)))
    }
}
impl Decimal<u32> {
    fn from_f32(val: f32) -> Self {
        let mut x: u32 = 0;
        {
            let mut val = (val - val.floor()).fract();
            for l in (1..u32::BITS).map(|i| { (0.5).powi(i as i32) } ) 
            {
                x += if val >= l {
                    val -= l;
                    1
                } else {
                    0
                };
                x <<= 1;
            }
        }
        Decimal(x)
    }
}

pub struct Array1<T: Num, const N: usize> {
    items: [T; N],
}
impl<T: Num + Copy, const N: usize> Array1<T, N> {
    fn new(items: [T; N]) -> Self {
        Array1 { items }
    }
    fn dot(&self, rhs: &Array1<T, N>) -> T {
        self.items
            .iter()
            .zip(rhs.items.iter())
            .map(|(&x, &y)| x * y)
            .fold(T::zero(), |sum, xy| sum + xy)
    }
}
impl<T: Num + Copy, const N: usize> Default for Array1<T, N> {
    fn default() -> Self {
        Self::new([T::zero(); N])
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_experiment() {
        // f32's memory usage
        // 1bit=d  ~ 符号 0=>+1,1=>-1
        // 8bit=A  ~ 指数 2^{A-127}
        // 23bit=B ~ 有効数 1.B
        // F:f32 = d * 2^{A-127} * 1.B

        let _f = |x: f32| {
            println!("=={}==", x);
            let bytes = x.fract().to_be_bytes();
            bytes.iter().for_each(|&x| print!("{:08b}", x));
            println!();
        };

        _f(0.5);
        _f(0.75);
        _f(0.625);
        _f(0.125);
        _f(-0.5);
        _f(-0.125);
        _f(0.33);
    }

    #[test]
    fn decimal_from_f32(){
        let test = |f:f32,respect:u32|{
            let Decimal(res) = Decimal::from_f32(f);
            assert_eq!(res,respect,"test for {}",f);
        };

        test(0.5,1<<(u32::BITS-1));
        test(0.25,1<<(u32::BITS-2));
        test(0.125,1<<(u32::BITS-3));
        test(-0.5,1<<(u32::BITS-1));
        test(-0.25,(1<<(u32::BITS-2))+(1<<(u32::BITS-1)));
    }

    #[test]
    fn array1_dot() {
        let x: Array1<u32, 3> = Array1::new([3, 4, 5]);
        let y: Array1<u32, 3> = Array1::new([1, 2, 3]);

        assert!(x.dot(&y) == 26)
    }
}
