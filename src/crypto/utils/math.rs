use array_macro::array;
use num::{
    traits::{Pow, WrappingAdd},
    Float, Num, One, ToPrimitive, Unsigned, Zero,
};
use rand::{prelude::ThreadRng, Rng};
use rand_distr::{Distribution, Normal, Uniform};
use std::ops::{Add, Mul, Neg, Sub};

pub trait Ring<T>: Cross<T, Output = Self> + Add + Sized {}
pub trait Cross<T> {
    type Output;
    fn cross(&self, rhs: &T) -> Self::Output;
}
/**
P(X) = SUM_{i=0}^{N-1} coefficient[i]X^i
を表す。
 */
#[derive(Debug, Clone, PartialEq)]
pub struct Polynomial<T, const N: usize> {
    coefficient: [T; N],
}
impl<S, T, const N: usize> Ring<S> for Polynomial<T, N>
where
    S: Copy,
    T: Copy + Mul<S, Output = T> + Add<Output = T>,
    Polynomial<T, N>: Cross<S, Output = Self>,
{
}
impl<S: Copy, T: Mul<S, Output = T> + Copy, const N: usize> Mul<S> for Polynomial<T, N> {
    type Output = Self;

    fn mul(self, rhs: S) -> Self::Output {
        let res: [T; N] = array![i => self.coefficient[i]*rhs;N];
        Polynomial { coefficient: res }
    }
}
impl<T: Add<Output = T> + Copy, const N: usize> Add for Polynomial<T, N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let res: [T; N] = array![i=> self.coefficient[i]+rhs.coefficient[i];N];
        Polynomial { coefficient: res }
    }
}
impl<
        S: Copy,
        T: Mul<S, Output = T> + Add<Output = T> + Sub<Output = T> + Copy + Zero,
        const N: usize,
    > Cross<Polynomial<S, N>> for Polynomial<T, N>
{
    type Output = Self;

    fn cross(&self, rhs: &Polynomial<S, N>) -> Self::Output {
        // TODO: FFTにするとO(nlog(n))、今はn^2
        let poly_cross = |l: &[T; N], r: &[S; N]| {
            let mut v = Vec::with_capacity(2 * N);
            for sum in 0..2 * N - 1 {
                v.push(T::zero());
                let l_lim = if sum < (N - 1) { 0 } else { sum - (N - 1) };
                let r_lim = sum.min(N - 1);
                // p(x)*q(x) = \sum_{s=0}^{2*(n-1)} \sum_{i=max(0,sum-(n-1))^{min(sum,n-1)} p_i * q_{sum-i}
                for j in l_lim..=r_lim {
                    v[sum] = v[sum] + l[sum - j] * r[j];
                }
            }
            v
        };
        // X^N+1で割ったあまりを返す
        let modulo = |pol: Vec<T>| {
            let res: [T; N] = array![i=>if i<N-1 { pol[i]-pol[N+i] } else {pol[i]};N];
            res
        };

        Polynomial {
            coefficient: modulo(poly_cross(&self.coefficient, &rhs.coefficient)),
        }
    }
}
impl<T: Neg<Output = T> + Copy, const N: usize> Neg for Polynomial<T, N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let l: [T; N] = array![i=>-self.coefficient[i];N];
        Polynomial::new(l)
    }
}
impl<T: Sub<Output = T> + Copy, const N: usize> Sub for Polynomial<T, N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let l: [T; N] = array![i=>self.coefficient[i]-rhs.coefficient[i];N];
        Polynomial::new(l)
    }
}
impl<T, const N: usize> Polynomial<T, N> {
    pub fn new(coeffis: [T; N]) -> Self {
        Polynomial {
            coefficient: coeffis,
        }
    }
    pub fn coefficient(&self) -> &[T; N] {
        &self.coefficient
    }
}
impl<T: Copy, const N: usize> Polynomial<T, N> {
    #[inline]
    pub fn coef_(&self, i: usize) -> T {
        self.coefficient[i]
    }
}
impl<const N: usize> Polynomial<Decimal<u32>, N> {
    pub fn decomposition<const L: usize>(&self, bits: u32) -> [Polynomial<i32, N>; L] {
        assert!(u32::BITS % bits == 0, "need to be divider of u32::BITS");

        let res: [[i32; L]; N] = array![ i => {
            self.coef_(i).decomposition(bits)
        }; N];

        array![ i => {
            Polynomial::new(array![ j => res[j][i]; N])
        }; L]
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
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
impl ToPrimitive for Binary {
    fn to_i64(&self) -> Option<i64> {
        Some(self.to_u64()? as i64)
    }

    fn to_u64(&self) -> Option<u64> {
        Some(match &self {
            Binary::One => u64::one(),
            Binary::Zero => u64::zero(),
        })
    }
}

pub trait Random<T> {
    fn gen(&mut self) -> T;
    fn gen_n<const N: usize>(&mut self) -> [T; N] {
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
    #[allow(dead_code)]
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
#[derive(Debug, PartialEq, Clone, Copy)]
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
    /// 2進表現から2^bits進表現に変換
    /// N=u32::BITSを2^bitsで表現したときの有効桁数
    pub fn decomposition<const L: usize>(self, bits: u32) -> [i32; L] {
        assert!((L as u32) * bits <= u32::BITS, "Wrong array size");
        const TOTAL: u32 = u32::BITS;
        let bg = 2_u32.pow(bits);
        let mask = bg - 1;
        let round = TOTAL - (L as u32) * bits > 0;

        let Decimal(u) = self;
        // 丸める
        let u = u + if round {
            2_u32.pow(TOTAL - (L as u32) * bits - 1)
        } else {
            0
        };
        // res={a_i}, a_i in [0,bg)
        let u_res = array![i => {
            (u >> (TOTAL - bits*((i+1) as u32))) & mask
        };L];
        // res={a_i}, a_i in [-bg/2,bg/2)
        let mut i_res = [i32::zero(); L];
        for i in (0..L).rev() {
            i_res[i] = if u_res[i] >= bg / 2 {
                if i > 0 {
                    i_res[i - 1] -= 1;
                }
                (u_res[i] as i32) - (bg as i32)
            } else {
                u_res[i] as i32
            }
        }
        i_res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polynomial_new() {
        let _interger_pol = Polynomial::new([2, 3, 4, 5]);
        let _float_pol = Polynomial::new([3.2, 4.5, 5.6, 7.8]);
        let _decimal_pol = Polynomial::new([Decimal(2_u32), Decimal(5_u32)]);
    }
    #[test]
    fn polynomial_add() {
        let l_integer = Polynomial::new([2, 3, 4, 5]);
        let r_integer = Polynomial::new([4, 5, 6, 7]);

        assert!((l_integer + r_integer).coefficient == [6, 8, 10, 12]);

        let l_dec = Polynomial::new([Decimal::from_f32(0.5), Decimal::from_f32(0.75)]);
        let r_dec = Polynomial::new([Decimal::from_f32(0.75), Decimal::from_f32(0.5)]);

        assert!((l_dec + r_dec).coefficient == [Decimal::from_f32(0.25), Decimal::from_f32(0.25)]);
    }
    #[test]
    fn polynomial_schalar() {
        let integer = Polynomial::new([2, 3, 4, 5]);

        assert!((integer * 3).coefficient == [6, 9, 12, 15]);

        let dec = Polynomial::new([Decimal::from_f32(0.5), Decimal::from_f32(0.75)]);

        assert!((dec * 3).coefficient == [Decimal::from_f32(0.5), Decimal::from_f32(0.25)]);
    }
    #[test]
    fn polynomial_cross() {
        let l_f = Polynomial::new([2, 3, 4]);
        let r_i = Polynomial::new([4, 5, 6]);

        assert_eq!((l_f.cross(&r_i)).coefficient, [-30, -2, 43]);

        let l_d = Polynomial::new([Decimal::from_f32(0.5), Decimal::from_f32(0.75)]);
        let r_i = Polynomial::new([2, 3]);

        let acc = 100;
        let res = (l_d.cross(&r_i)).coefficient;
        assert!(range_eq(res[0].0, Decimal::from_f32(0.75).0, acc));
        assert!(range_eq(res[1].0, Decimal::from_f32(0.0).0, acc));
    }
    #[test]
    fn polynomial_decomposition() {
        let pol = Polynomial::new([Decimal(0x8000_0000_u32)]);
        let res = pol.decomposition::<7>(4);
        assert_eq!(
            res,
            {
                let coef = pol.coef_(0);
                let decomp = coef.decomposition::<7>(4);
                array![ i => {
                    Polynomial::new([decomp[i]])
                };7]
            },
            "要素数1のPolynomialを展開"
        );

        let pol = Polynomial::new([Decimal(0x0000_0001_u32), Decimal(0x0002_8000_u32)]);
        let res = pol.decomposition::<2>(16);
        assert_eq!(
            res,
            [Polynomial::new([0, 2]), Polynomial::new([1, -32768])],
            "要素数2のPolynomialを展開"
        );
    }

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
        let test = |f: f32, g: f32| {
            let res = Decimal::from_f32(f);
            assert!(
                (res.to_f32().unwrap() - g).abs() < f32::EPSILON,
                "test for {}",
                f
            );
        };

        test(0.5, 0.5);
        test(0.25, 0.25);
        test(-0.25, 0.75);
        test(0.4, 0.4);
        test(0.123, 0.123);
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
    fn decimal_decomposition() {
        let dec = Decimal(0x80000000_u32);
        let res = dec.decomposition::<32>(1);
        assert_eq!(
            res,
            [
                -1_i32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
            ],
            "test1"
        );

        let res = dec.decomposition::<8>(4);
        assert_eq!(res, [-8_i32, 0, 0, 0, 0, 0, 0, 0], "test2");
        let res = dec.decomposition::<7>(4);
        assert_eq!(res, [-8_i32, 0, 0, 0, 0, 0, 0], "test2");
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
