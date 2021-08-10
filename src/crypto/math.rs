use std::ops::{Add, Mul, Neg};

use num::{traits::WrappingAdd, Float, Num, ToPrimitive, Unsigned};
use rand::{prelude::ThreadRng, Rng};
use rand_distr::{Distribution, Normal, Uniform};

#[derive(Debug)]
pub enum Binary {
    One = 1,
    Zero = 0,
}
impl Binary {
    fn from<T: Num>(t: T) -> Binary {
        if t == T::zero() {
            Binary::Zero
        } else {
            Binary::One
        }
    }
}

trait Random<T> {
    fn gen(&mut self) -> T;
}
#[derive(Debug)]
struct ModGuassian<R: Rng> {
    normal: Normal<f32>,
    rng: R,
}
impl<R: Rng> Random<Decimal<u32>> for ModGuassian<R> {
    fn gen(&mut self) -> Decimal<u32> {
        let r = self.normal.sample(&mut self.rng);
        Decimal::from_f32(r)
    }
}
impl ModGuassian<ThreadRng> {
    fn new(std_dev: f32) -> Self {
        ModGuassian {
            normal: Normal::new(f32::neg_zero(), std_dev).unwrap(),
            rng: rand::thread_rng(),
        }
    }
}
struct ModUniform<R: Rng> {
    uniform: Uniform<f32>,
    rng: R,
}
impl<R: Rng> Random<Decimal<u32>> for ModUniform<R> {
    fn gen(&mut self) -> Decimal<u32> {
        Decimal::from_f32(self.uniform.sample(&mut self.rng))
    }
}
impl ModUniform<ThreadRng> {
    fn new() -> Self {
        ModUniform {
            uniform: Uniform::new(0.0, 1.0),
            rng: rand::thread_rng(),
        }
    }
}

struct BinaryUniform<R: Rng> {
    uniform: Uniform<i32>,
    rng: R,
}
impl<R: Rng> Random<Binary> for BinaryUniform<R> {
    fn gen(&mut self) -> Binary {
        Binary::from(self.uniform.sample(&mut self.rng))
    }
}
impl BinaryUniform<ThreadRng> {
    fn new() -> Self {
        BinaryUniform {
            uniform: Uniform::new(0, 2),
            rng: rand::thread_rng(),
        }
    }
}

/**
  0.5 = 101000...
  0.8 = 000100...
  Ex.  0.5 + 0.625
  = 100000.. + 10100... = 0010000... = 0.125
  Ex.  0.5 * 3
  = 100000.. * 3 = 100000.. = 0.5
*/
#[derive(Debug, PartialEq)]
pub struct Decimal<U: Unsigned>(U);
impl<U: Unsigned + WrappingAdd> Add for Decimal<U> {
    type Output = Decimal<U>;

    fn add(self, rhs: Self) -> Self::Output {
        Decimal(self.0.wrapping_add(&rhs.0))
    }
}
impl<T: ToPrimitive> Mul<T> for Decimal<u32> {
    type Output = Decimal<u32>;

    fn mul(self, rhs: T) -> Self::Output {
        Decimal(self.0.wrapping_mul(rhs.to_u32().unwrap()))
    }
}
impl Neg for Decimal<u32> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Decimal(u32::MAX - self.0)
    }
}
impl Decimal<u32> {
    // floatのメモリ的に有効数字2進24桁なので、その範囲で構成。
    fn from_f32(val: f32) -> Self {
        let mut x: u32 = 0;
        {
            let f_acc = f32::MANTISSA_DIGITS;
            let end = u32::BITS;

            let mut val = (val - val.floor()).fract();
            for i in 1..f_acc {
                let l = (0.5).powi(i as i32);
                x += if val >= l {
                    val -= l;
                    1
                } else {
                    0
                };
                x <<= 1
            }
            x <<= end - f_acc;
        }
        Decimal(x)
    }
}

/**
内積を定義するための配列ラップ
ベクトル演算は下に実装
 */
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
    use std::ops::Sub;

    use super::*;

    #[test]
    fn mod_guassian_run() {
        let mut mg = ModGuassian::new(1.0);

        for _ in 0..50 {
            println!("{:?}", mg.gen());
        }
    }

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
    fn decimal_from_f32() {
        let test = |f: f32, respect: u32| {
            let Decimal(res) = Decimal::from_f32(f);
            assert_eq!(res, respect, "test for {}", f);
        };

        test(0.5, 1 << (u32::BITS - 1));
        test(0.25, 1 << (u32::BITS - 2));
        test(0.125, 1 << (u32::BITS - 3));
        test(-0.5, 1 << (u32::BITS - 1));
        test(-0.25, (1 << (u32::BITS - 2)) + (1 << (u32::BITS - 1)));
    }
    #[test]
    fn decimal_add() {
        let test = |x: f32, y: f32, z: f32| {
            let dx = Decimal::from_f32(x);
            let dy = Decimal::from_f32(y);
            let Decimal(result) = dx + dy;
            let Decimal(expect) = Decimal::from_f32(z);

            assert_eq!(
                result,
                expect,
                "test for {}+{} == {} ?\n result={:?},respect={:?}",
                x,
                y,
                z,
                Decimal(result),
                Decimal(expect)
            );
        };

        test(0.5, 0.5, 0.0);
        test(0.25, 0.25, 0.5);
        test(0.5, 0.75, 0.25);
        test(0.75, -0.25, 0.5);
        test(0.4, 0.7, 0.1);
        test(0.67, 0.41, 0.08);
        test(0.524, 0.623, 0.147);
    }
    #[test]
    fn decimal_mul() {
        let acc: u32 = 2000; // これくらいの精度は出る。有効数字6桁くらい

        let test = |x: f32, y: u32, z: f32| {
            let dx = Decimal::from_f32(x);
            let Decimal(result) = dx * y;
            let Decimal(respect) = Decimal::from_f32(z);

            assert!(
                range_eq(result, respect, acc),
                "test for {}*{} == {} ?\n result={:?},respect={:?}",
                x,
                y,
                z,
                Decimal(result),
                Decimal(respect)
            );
        };

        test(0.5, 1, 0.5);
        test(0.25, 2, 0.5);
        test(0.5, 2, 0.0);
        test(0.75, 4, 0.0);
        test(0.4, 3, 0.2);
        test(0.67, 2, 0.34);
        test(0.524, 5, 0.62);
    }
    #[test]
    fn decimal_neg() {
        let test = |x: f32| {
            let acc: u32 = 100;

            let dec = Decimal::from_f32(x);
            let Decimal(expect) = Decimal::from_f32(-x);
            let Decimal(result) = -dec;

            assert!(
                range_eq(result, expect, acc),
                "result={:?},expect={:?}",
                Decimal(result),
                Decimal(expect)
            );
        };

        test(0.5);
        test(-0.25);
        test(0.125);
        test(0.4);
    }

    #[test]
    fn array1_dot() {
        let x: Array1<u32, 3> = Array1::new([3, 4, 5]);
        let y: Array1<u32, 3> = Array1::new([1, 2, 3]);

        assert!(x.dot(&y) == 26)
    }

    fn range_eq<T: Num + PartialOrd>(result: T, expect: T, acc: T) -> bool {
        let diff: T = if result > expect {
            result - expect
        } else {
            expect - result
        };
        acc > diff
    }
}
