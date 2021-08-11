use std::ops::{Add, Mul, Neg, Sub};
use array_macro::array;
use num::{Float, Num, One, ToPrimitive, Unsigned, Zero, traits::WrappingAdd};
use rand::{prelude::ThreadRng, Rng};
use rand_distr::{Distribution, Normal, Uniform};

#[derive(Debug,Clone, Copy,PartialEq)]
pub enum Binary {
    One = 1,
    Zero = 0,
}
impl Binary {
    pub fn from<T: Num>(t: T) -> Binary {
        if t == T::zero() {
            Binary::Zero
        } else {
            Binary::One
        }
    }
    pub fn to<T: Num>(&self) -> T {
        match self {
            Binary::One => T::one(),
            Binary::Zero => T::zero(),
        }
    }
}

pub trait Random<T> {
    fn gen(&mut self) -> T;
    fn genN<const N: usize>(&mut self) -> [T; N] {
        let l: [T; N] = array![_ => self.gen(); N];
        l
    }
}
#[derive(Debug)]
pub struct ModDistribution<X: Distribution<f32>, R: Rng> {
    distr: X,
    rng: R,
}
impl<X: Distribution<f32>, R: Rng> Random<Decimal<u32>> for ModDistribution<X, R> {
    fn gen(&mut self) -> Decimal<u32> {
        let r = self.distr.sample(&mut self.rng);
        Decimal::from_f32(r)
    }
}
impl ModDistribution<Normal<f32>, ThreadRng> {
    pub fn gaussian(std_dev: f32) -> Self {
        ModDistribution {
            distr: Normal::new(f32::neg_zero(), std_dev).unwrap(),
            rng: rand::thread_rng(),
        }
    }
}
impl ModDistribution<Uniform<f32>, ThreadRng> {
    pub fn uniform() -> Self {
        ModDistribution {
            distr: Uniform::new(0.0, 1.0),
            rng: rand::thread_rng(),
        }
    }
}

pub struct BinaryDistribution<X: Distribution<i32>, R: Rng> {
    uniform: X,
    rng: R,
}
impl<X: Distribution<i32>, R: Rng> Random<Binary> for BinaryDistribution<X, R> {
    fn gen(&mut self) -> Binary {
        Binary::from(self.uniform.sample(&mut self.rng))
    }
}
impl BinaryDistribution<Uniform<i32>, ThreadRng> {
    pub fn uniform() -> BinaryDistribution<Uniform<i32>, ThreadRng> {
        BinaryDistribution {
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
#[derive(Debug, PartialEq,Clone, Copy)]
pub struct Decimal<U: Unsigned>(U);
impl<U: Unsigned + WrappingAdd> Add for Decimal<U> {
    type Output = Decimal<U>;

    fn add(self, rhs: Self) -> Self::Output {
        Decimal(self.0.wrapping_add(&rhs.0))
    }
}
pub type Torus = Decimal<u32>;
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
impl ToPrimitive for Decimal<u32> {
    fn to_i64(&self) -> Option<i64> {
        Some(0)
    }

    fn to_u64(&self) -> Option<u64> {
        Some(0)
    }

    fn to_isize(&self) -> Option<isize> {
        Some(0)
    }

    fn to_i8(&self) -> Option<i8> {
        Some(0)
    }

    fn to_i16(&self) -> Option<i16> {
        Some(0)
    }

    fn to_i32(&self) -> Option<i32> {
        Some(0)
    }

    fn to_i128(&self) -> Option<i128> {
        Some(0)
    }

    fn to_usize(&self) -> Option<usize> {
        Some(0)
    }

    fn to_u8(&self) -> Option<u8> {
        Some(0)
    }

    fn to_u16(&self) -> Option<u16> {
        Some(0)
    }

    fn to_u32(&self) -> Option<u32> {
        Some(0)
    }

    fn to_u128(&self) -> Option<u128> {
        Some(0)
    }

    fn to_f32(&self) -> Option<f32> {
        let n = f32::MANTISSA_DIGITS;
        let mut u = self.0;
        u >>= 32 - n;
        let f = (1..=n)
            .map(|i| (0.5).powi(i as i32))
            .rev()
            .filter(|_| {
                let flag = if u & 1 > 0 { true } else { false };
                u >>= 1;
                flag
            })
            .fold(f32::neg_zero(), |s, x| s + x);
        Some(f)
    }

    fn to_f64(&self) -> Option<f64> {
        match self.to_f32() {
            Some(f) => Some(f as f64),
            None => None,
        }
    }
}
impl One for Decimal<u32> {
    fn one() -> Self {
        Decimal(u32::MAX)
    }
}
impl Zero for Decimal<u32> {
    fn zero() -> Self {
        Decimal(u32::zero())
    }

    fn is_zero(&self) -> bool {
        u32::is_zero(&self.0)
    }
}
impl Sub for Decimal<u32> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}
impl Decimal<u32> {
    // floatのメモリ的に有効数字2進24桁なので、その範囲で構成。
    pub fn from_f32(val: f32) -> Self {
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
    use super::*;

    #[test]
    fn mod_guassian_run() {
        let mut mg = ModDistribution::gaussian(1.0);

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
    fn decimal_to_f32() {
        let test = |f: f32,g: f32| {
            let res = Decimal::from_f32(f);
            assert!((res.to_f32().unwrap()-g).abs() < f32::EPSILON, "test for {}", f);
        };

        test(0.5,0.5);
        test(0.25,0.25);
        test(-0.25,0.75);
        test(0.4,0.4);
        test(0.123,0.123);
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
