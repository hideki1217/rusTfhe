use crate::mem;
use crate::spqlios::FrrSeries;
use crate::spqlios::Spqlios;
use num::{
    traits::{MulAdd, WrappingAdd, WrappingSub},
    Complex, Float, Integer, One, ToPrimitive, Unsigned, Zero,
};
use rand::{prelude::ThreadRng, Rng};
use rand_distr::{Distribution, Normal, Uniform};
use std::{cell::RefCell, ops::Index};
use std::{
    collections::HashMap,
    fmt::Display,
    mem::MaybeUninit,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

//Macro
#[macro_export]
macro_rules! pol {
    ($e:expr) => {
        Polynomial::new($e)
    };
}
#[macro_export]
macro_rules! torus {
    ($e:expr) => {
        Torus32::from($e)
    };
}

pub trait Cross<T> {
    type Output;
    fn cross(&self, rhs: &T) -> Self::Output;
}
/**
P(X) = SUM_{i=0}^{N-1} 0\[i\]X^i
を表す。
X^N+1を法とした剰余環上の値
 */
#[derive(Debug, Clone, PartialEq)]
pub struct Polynomial<T, const N: usize>([T; N]);
impl<T, const N: usize> Polynomial<T, N> {
    pub fn new(coeffis: [T; N]) -> Self {
        Polynomial(coeffis)
    }
    pub fn coefs(&self) -> &[T; N] {
        &self.0
    }
    pub fn coefs_mut(&mut self) -> &mut [T; N] {
        &mut self.0
    }
    pub fn map<O, F: Fn(&T) -> O>(&self, f: F) -> Polynomial<O, N> {
        let mut arr: [MaybeUninit<O>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        self.0
            .iter()
            .zip(arr.iter_mut())
            .for_each(|(t, x)| *x = MaybeUninit::new(f(t)));
        pol!(crate::mem::transmute::<_, [O; N]>(arr))
    }
}
impl<T, const N: usize> Index<usize> for Polynomial<T, N> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        &self.coefs()[index]
    }
}
impl<T: Copy, const N: usize> Polynomial<T, N> {
    #[inline]
    pub fn coef_(&self, i: usize) -> T {
        self.coefs()[i]
    }
}
impl<T: Neg<Output = T> + Copy, const N: usize> Polynomial<T, N> {
    /// # Expamle
    /// ```
    /// use utils::{pol,math::Polynomial};
    /// assert_eq!(pol!([1,2,3,4,5]).rotate(1),pol!([-5,1,2,3,4]));
    /// assert_eq!(pol!([1,2,3,4,5]).rotate(-1),pol!([2,3,4,5,-1]));
    /// assert_eq!(pol!([1,2,3,4,5]).rotate(5),pol!([-1,-2,-3,-4,-5]));
    /// assert_eq!(pol!([1,2,3,4,5]).rotate(-4),pol!([5,-1,-2,-3,-4]));
    /// assert_eq!(pol!([1,2,3,4,5]).rotate(-8),pol!([1,2,3,4,5]).rotate(2));
    /// assert_eq!(pol!([1,2,3,4,5]).rotate(10),pol!([1,2,3,4,5]));
    /// ```
    pub fn rotate(&self, n: i32) -> Self {
        let n = n.mod_floor(&(2 * N as i32)) as usize;
        let mut arr: [MaybeUninit<T>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        if n <= N {
            let n: usize = n as usize;
            let (arr_m, arr_p) = arr.split_at_mut(n);
            let (coef_p, coef_m) = self.coefs().split_at(N - n);
            arr_m
                .iter_mut()
                .zip(coef_m.iter().map(|&t| -t))
                .for_each(|(x, c)| *x = MaybeUninit::new(c));
            arr_p
                .iter_mut()
                .zip(coef_p.iter())
                .for_each(|(x, &c)| *x = MaybeUninit::new(c));
        } else {
            let n: usize = n as usize - N;
            let (arr_p, arr_m) = arr.split_at_mut(n);
            let (coef_m, coef_p) = self.coefs().split_at(N - n);
            arr_m
                .iter_mut()
                .zip(coef_m.iter().map(|&t| -t))
                .for_each(|(x, c)| *x = MaybeUninit::new(c));
            arr_p
                .iter_mut()
                .zip(coef_p.iter())
                .for_each(|(x, &c)| *x = MaybeUninit::new(c));
        }
        pol!(mem::transmute(arr))
        /*
        let n = n.mod_floor(&(2 * N as i32)) as usize;
        if n <= N {
            let n: usize = n as usize;
            pol!(mem::array_create_enumerate(|i| if i < n {
                -self.coef_(N + i - n)
            } else {
                self.coef_(i - n)
            }))
        } else {
            let n: usize = (2 * N - n) as usize;
            pol!(mem::array_create_enumerate(|i| if i + n >= N {
                -self.coef_(i + n - N)
            } else {
                self.coef_(n + i)
            }))
        }
        */
    }
}
impl<T: AddAssign + Copy, const N: usize> Polynomial<T, N> {
    pub fn add_constant(&mut self, rhs: T) {
        self.coefs_mut()[0] += rhs;
    }
}
impl<S: Copy, T: Mul<S, Output = T> + Copy, const N: usize> Mul<S> for Polynomial<T, N> {
    type Output = Self;
    fn mul(mut self, rhs: S) -> Self::Output {
        self.coefs_mut().iter_mut().for_each(|x| *x = *x * rhs);
        self
    }
}
impl<S: Copy, T: Add<S, Output = T> + Copy, const N: usize> Add<Polynomial<S, N>>
    for Polynomial<T, N>
{
    type Output = Self;
    fn add(self, rhs: Polynomial<S, N>) -> Self::Output {
        self.add(&rhs)
    }
}
impl<S: Copy, T: Add<S, Output = T> + Copy, const N: usize> Add<&Polynomial<S, N>>
    for Polynomial<T, N>
{
    type Output = Self;
    fn add(mut self, rhs: &Polynomial<S, N>) -> Self::Output {
        self.coefs_mut()
            .iter_mut()
            .zip(rhs.coefs().iter())
            .for_each(|(x, &y)| *x = *x + y);
        self
    }
}
impl<S: Copy, T: Add<S, Output = T> + Copy, const N: usize> AddAssign<Polynomial<S, N>>
    for Polynomial<T, N>
{
    fn add_assign(&mut self, rhs: Polynomial<S, N>) {
        self.add_assign(&rhs)
    }
}
impl<S: Copy, T: Add<S, Output = T> + Copy, const N: usize> AddAssign<&Polynomial<S, N>>
    for Polynomial<T, N>
{
    fn add_assign(&mut self, rhs: &Polynomial<S, N>) {
        self.coefs_mut()
            .iter_mut()
            .zip(rhs.coefs().iter())
            .for_each(|(x, &y)| *x = *x + y);
    }
}
impl<S, T, const N: usize> MulAdd<&Polynomial<S, N>, Polynomial<T, N>> for &Polynomial<T, N>
where
    T: MulAdd<S, Output = T> + Zero + Copy + Sub<Output = T>,
    S: Copy,
{
    type Output = Polynomial<T, N>;
    fn mul_add(self, a: &Polynomial<S, N>, mut b: Polynomial<T, N>) -> Self::Output {
        b.coefs_mut().iter_mut().enumerate().for_each(|(k, b_)| {
            *b_ = *b_
                + if k < N - 1 {
                    convolution(self.coefs(), a.coefs(), k)
                        - convolution(self.coefs(), a.coefs(), k + N)
                } else {
                    convolution(self.coefs(), a.coefs(), k)
                };
        });
        b
    }
}
impl<T: Neg<Output = T> + Copy, const N: usize> Neg for Polynomial<T, N> {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        self.coefs_mut().iter_mut().for_each(|x| *x = -*x);
        self
    }
}
impl<S: Copy, T: Sub<S, Output = T> + Copy, const N: usize> Sub<Polynomial<S, N>>
    for Polynomial<T, N>
{
    type Output = Self;
    fn sub(self, rhs: Polynomial<S, N>) -> Self::Output {
        self.sub(&rhs)
    }
}
impl<S: Copy, T: Sub<S, Output = T> + Copy, const N: usize> Sub<&Polynomial<S, N>>
    for Polynomial<T, N>
{
    type Output = Self;
    fn sub(mut self, rhs: &Polynomial<S, N>) -> Self::Output {
        self.coefs_mut()
            .iter_mut()
            .zip(rhs.coefs().iter())
            .for_each(|(x, &y)| *x = *x - y);
        self
    }
}
impl<T: Zero + Copy, const N: usize> Zero for Polynomial<T, N> {
    fn zero() -> Self {
        pol!([T::zero(); N])
    }
    fn is_zero(&self) -> bool {
        self.0.iter().all(|t| t.is_zero())
    }
}
/// X^N+1を法とした多項式乗算
impl<S: Copy, T: Sub<Output = T> + Copy + Zero + MulAdd<S, Output = T>, const N: usize>
    Cross<Polynomial<S, N>> for Polynomial<T, N>
{
    type Output = Self;
    fn cross(&self, rhs: &Polynomial<S, N>) -> Self::Output {
        let mut arr: [MaybeUninit<T>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        for (sum, arr_i) in arr.iter_mut().enumerate() {
            // p(x)*q(x) = \sum_{s=0}^{2*(n-1)} \sum_{i=max(0,sum-(n-1))^{min(sum,n-1)} p_i * q_{sum-i} mod X^N+1
            if sum < N - 1 {
                *arr_i = MaybeUninit::new(
                    convolution(self.coefs(), rhs.coefs(), sum)
                        - convolution(self.coefs(), rhs.coefs(), N + sum),
                );
            } else {
                *arr_i = MaybeUninit::new(convolution(self.coefs(), rhs.coefs(), sum));
            }
        }
        Polynomial(mem::transmute::<_, [T; N]>(arr))
    }
}
impl<const N: usize> From<&Polynomial<i32, N>> for FrrSeries<N> {
    fn from(pol: &Polynomial<i32, N>) -> Self {
        FFT_MAP.with(|m| m.borrow_mut().get_fft_proc(N).ifft_int(&pol.0))
    }
}
impl<const N: usize> From<&Polynomial<Binary, N>> for FrrSeries<N> {
    fn from(pol: &Polynomial<Binary, N>) -> Self {
        let pol = mem::array_create_enumerate(|i| pol[i] as i32);
        FFT_MAP.with(|m| m.borrow_mut().get_fft_proc(N).ifft_int(&pol))
    }
}
impl<const N: usize> From<&Polynomial<Torus32, N>> for FrrSeries<N> {
    fn from(pol: &Polynomial<Torus32, N>) -> Self {
        FFT_MAP.with(|m| m.borrow_mut().get_fft_proc(N).ifft_torus(&pol.0))
    }
}
impl<const N: usize> From<&Polynomial<f64, N>> for FrrSeries<N> {
    fn from(pol: &Polynomial<f64, N>) -> Self {
        FFT_MAP.with(|m| m.borrow_mut().get_fft_proc(N).ifft(&pol.0))
    }
}
impl<const N: usize> From<&FrrSeries<N>> for Polynomial<Torus32, N> {
    fn from(s: &FrrSeries<N>) -> Self {
        pol!(FFT_MAP.with(|m| m.borrow_mut().get_fft_proc(N).fft_torus(s)))
    }
}
impl<const N: usize> From<FrrSeries<N>> for Polynomial<Torus32, N> {
    fn from(s: FrrSeries<N>) -> Self {
        Self::from(&s)
    }
}
impl<const N: usize> From<&FrrSeries<N>> for Polynomial<f64, N> {
    fn from(s: &FrrSeries<N>) -> Self {
        pol!(FFT_MAP.with(|m| m.borrow_mut().get_fft_proc(N).fft(s)))
    }
}
impl<const N: usize> From<FrrSeries<N>> for Polynomial<f64, N> {
    fn from(s: FrrSeries<N>) -> Self {
        Self::from(&s)
    }
}
impl<const N: usize> Polynomial<Decimal<u32>, N> {
    pub fn decomposition_i32_<const L: usize>(
        &self,
        bits: u32,
        decomp_mask: u32,
    ) -> [Polynomial<i32, N>; L] {
        let mut res: [[MaybeUninit<i32>; N]; L] = unsafe { MaybeUninit::uninit().assume_init() };
        let masked_coefs: [Decimal<u32>; N] = unsafe {
            mem::array_create(
                self.coefs()
                    .iter()
                    .map(|d| Decimal::from_bits(d.inner().wrapping_add(decomp_mask) ^ decomp_mask)),
            )
        };
        let mask: u32 = (1 << bits) - 1;
        for (i, res_i) in res.iter_mut().enumerate() {
            for (coef_i, res_i_j) in masked_coefs.iter().zip(res_i.iter_mut()) {
                let u = (coef_i.inner() >> (u32::BITS - bits * ((i + 1) as u32))) & mask;
                // uはbits桁の符号付き表現になっている。bits -> 32へ符号拡張する
                *res_i_j = MaybeUninit::new(
                    (u & (1 << (bits - 1)))
                        .wrapping_mul(0xfffffffe_u32)
                        .wrapping_add(u) as i32,
                );
            }
        }
        mem::transmute(res)
    }
    pub fn decomposition_i32<const L: usize>(&self, bits: u32) -> [Polynomial<i32, N>; L] {
        let res_: [[i32; L]; N] =
            unsafe { mem::array_create(self.coefs().iter().map(|d| d.decomposition_i32(bits))) };

        mem::array_create_enumerate(|i| pol!(mem::array_create_enumerate(|j| res_[j][i])))
    }
}
impl<T, const N: usize> Polynomial<T, N> {
    /// # Panic
    /// - 'self.len() % 2 > 0'
    pub fn fft_cross<'a, S>(&'a self, rhs: &'a Polynomial<S, N>) -> Self
    where
        FrrSeries<N>: From<&'a Polynomial<T, N>> + From<&'a Polynomial<S, N>>,
        Polynomial<T, N>: From<FrrSeries<N>>,
    {
        let lhs_f = FrrSeries::<N>::from(self);
        let rhs_f = FrrSeries::<N>::from(rhs);
        // 要素積
        let res_f = lhs_f.hadamard(&rhs_f);
        res_f.into()
    }
}
thread_local! {
    pub static FFT_MAP: RefCell<FftMap> = Default::default();
}
#[derive(Default)]
pub struct FftMap(HashMap<usize, Spqlios>);
impl FftMap {
    pub fn get_fft_proc(&mut self, n: usize) -> &mut Spqlios {
        self.0
            .entry(n)
            .or_insert_with(|| *Box::new(Spqlios::new(n)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Binary {
    One = 1,
    Zero = 0,
}
impl<T: Zero + PartialEq> From<T> for Binary {
    fn from(t: T) -> Self {
        if t == T::zero() {
            Binary::Zero
        } else {
            Binary::One
        }
    }
}
macro_rules! binary_into {
    ($t:ty) => {
        impl Into<$t> for Binary {
            fn into(self) -> $t {
                match self {
                    Binary::One => <$t>::one(),
                    Binary::Zero => <$t>::zero(),
                }
            }
        }
    };
}
binary_into!(f64);
binary_into!(f32);
binary_into!(i32);
binary_into!(u32);

impl Display for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (*self as u32).fmt(f)
    }
}

pub trait Random<T> {
    fn gen(&mut self) -> T;
    fn gen_n<const N: usize>(&mut self) -> [T; N] {
        let l: [T; N] = mem::array_create_enumerate(|_| self.gen());
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
        torus!(r)
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

pub struct ComplexDistribution<X: Distribution<f64>, R: Rng> {
    distr: X,
    rng: R,
}
impl<X: Distribution<f64>, R: Rng> Random<Complex<f64>> for ComplexDistribution<X, R> {
    fn gen(&mut self) -> Complex<f64> {
        let r = self.distr.sample(&mut self.rng);
        let i = self.distr.sample(&mut self.rng);
        Complex::new(r, i)
    }
}
impl ComplexDistribution<Normal<f64>, ThreadRng> {
    pub fn gaussian(std_dev: f64) -> Self {
        ComplexDistribution {
            distr: Normal::new(f64::neg_zero(), std_dev).unwrap(),
            rng: rand::thread_rng(),
        }
    }
}
impl ComplexDistribution<Uniform<f64>, ThreadRng> {
    pub fn uniform() -> Self {
        ComplexDistribution {
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
impl<U: Unsigned> Decimal<U> {
    pub fn from_bits(u: U) -> Self {
        Decimal(u)
    }
}
impl<U: Unsigned + Copy> Decimal<U> {
    #[inline]
    pub fn inner(&self) -> U {
        self.0
    }
}
impl<U: Unsigned + WrappingAdd> Add for Decimal<U> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Decimal(self.0.wrapping_add(&rhs.0))
    }
}
impl<U: Unsigned + WrappingAdd> AddAssign for Decimal<U> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.wrapping_add(&rhs.0);
    }
}
impl<U: Unsigned + WrappingSub> Sub for Decimal<U> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Decimal(self.0.wrapping_sub(&rhs.0))
    }
}
impl<U: Unsigned + WrappingSub> SubAssign for Decimal<U> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.wrapping_sub(&rhs.0);
    }
}
impl<U: Unsigned + WrappingSub> Neg for Decimal<U> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Decimal(U::zero().wrapping_sub(&self.0))
    }
}
impl<U: Unsigned + Zero + WrappingAdd> Zero for Decimal<U> {
    fn zero() -> Self {
        Decimal(U::zero())
    }
    fn is_zero(&self) -> bool {
        U::is_zero(&self.0)
    }
}
// 以下 Torus
pub type Torus32 = Decimal<u32>;
impl Decimal<u32> {
    #[allow(dead_code)]
    pub const fn make_decomp_mask(l: u32, bits: u32) -> u32 {
        let total = u32::BITS;
        let mut u = 0_u32;
        if (total - l * bits) != 0 {
            u = u.wrapping_add(1 << (total - l * bits - 1));
            let mut i = l;
            while i >= 1 {
                u += 1 << (total - i * bits - 1);
                i -= 1;
            }
        } else {
            let mut i = l - 1;
            while i >= 1 {
                u += 1 << (total - i * bits - 1);
                i -= 1;
            }
        }
        u
    }
    pub fn decomposition_i32_<const L: usize>(self, bits: u32, decomp_mask: u32) -> [i32; L] {
        const TOTAL: u32 = u32::BITS;
        let u = self.inner().wrapping_add(decomp_mask) ^ decomp_mask;

        let mask: u32 = (1 << bits) - 1;
        let mut res: [MaybeUninit<i32>; L] = unsafe { MaybeUninit::uninit().assume_init() };
        res.iter_mut().enumerate().for_each(|(i, res_i)| {
            let u = (u >> (TOTAL - bits * ((i + 1) as u32))) & mask;
            // uはbits桁の符号付き表現になっている。bits -> 32へ符号拡張する
            *res_i = MaybeUninit::new(
                (u & (1 << (bits - 1)))
                    .wrapping_mul(0xfffffffe_u32)
                    .wrapping_add(u) as i32,
            );
        });
        mem::transmute::<_, [i32; L]>(res)
    }
    /// 2進表現から2^bits進表現に変換
    /// - res\[i\] in [-bg/2,bg/2) where bg = 2^bits
    /// - N=u32::BITSを2^bitsで表現したときの有効桁数
    pub fn decomposition_i32<const L: usize>(self, bits: u32) -> [i32; L] {
        let decomp_mask = {
            // inlined make_decomp_mask(L,bits) const Value
            const TOTAL: u32 = u32::BITS;
            if (TOTAL - L as u32 * bits) != 0 {
                // with round
                (1..=L as u32).fold(0_u32, |s, i| s | 1 << (TOTAL - i * bits - 1))
            } else {
                (1..L as u32).fold(0_u32, |s, i| s | 1 << (TOTAL - i * bits - 1))
            }
        };
        self.decomposition_i32_(bits, decomp_mask)
    }

    /// 2進表現から2^bits進表現に変換
    /// - res\[i\] in [0,bg) where bg = 2^{bits}
    /// - N=u32::BITSを2^bitsで表現したときの有効桁数
    pub fn decomposition_u32<const L: usize>(self, bits: u32) -> [u32; L] {
        debug_assert!((L as u32) * bits <= u32::BITS, "Wrong array size");
        const TOTAL: u32 = u32::BITS;

        let Decimal(u) = self;
        // 丸める
        let u = u.wrapping_add(if (TOTAL - (L as u32) * bits) != 0 {
            1 << (TOTAL - (L as u32) * bits - 1)
        } else {
            0
        });

        let mask = (1 << bits) - 1;
        // res={a_i}, a_i in [0,bg)
        let u_res =
            mem::array_create_enumerate(|i| (u >> (TOTAL - bits * ((i + 1) as u32))) & mask);
        u_res
    }

    pub fn is_in(&self, p: Self, acc: f32) -> bool {
        let x: f32 = self.into();
        let p: f32 = p.into();
        (x - p).abs() < acc
    }
    /// ```
    /// use std::convert::From;
    /// use utils::math::Torus32;
    /// assert!(Torus32::pow_two_minus(1).is_in(Torus32::from(0.5),1e-6));
    /// assert!(Torus32::pow_two_minus(0).is_in(Torus32::from(1.0),1e-6));
    /// assert!(Torus32::pow_two_minus(31).is_in(Torus32::from(0.5_f32.powi(31)),1e-6));
    /// assert!(Torus32::pow_two_minus(32).is_in(Torus32::from(0.0),1e-6));
    /// ```
    pub fn pow_two_minus(n: u32) -> Self {
        if n == 0 {
            return Torus32::from_bits(0);
        }
        let n = n.min(32);
        Torus32::from_bits((1 << (32 - n)))
    }
}
impl Mul<u32> for Decimal<u32> {
    type Output = Self;
    fn mul(self, rhs: u32) -> Self::Output {
        Decimal(self.0.wrapping_mul(rhs.to_u32().unwrap()))
    }
}
impl Mul<i32> for Decimal<u32> {
    type Output = Self;
    fn mul(self, rhs: i32) -> Self::Output {
        if rhs.is_negative() {
            -(self * rhs.abs() as u32)
        } else {
            self * rhs as u32
        }
    }
}
impl Mul<Binary> for Decimal<u32> {
    type Output = Self;
    fn mul(self, rhs: Binary) -> Self::Output {
        self * rhs as u32
    }
}
impl<T> MulAdd<T> for Decimal<u32>
where
    Self: Mul<T, Output = Self>,
{
    type Output = Self;
    fn mul_add(self, a: T, b: Self) -> Self::Output {
        self * a + b
    }
}
impl Into<f64> for Decimal<u32> {
    fn into(self) -> f64 {
        (&self).into()
    }
}
impl Into<f64> for &Decimal<u32> {
    fn into(self) -> f64 {
        const X: f64 = 1.0 / (u32::MAX as f64);
        (self.0 as f64) * X
    }
}
impl Into<f32> for Decimal<u32> {
    fn into(self) -> f32 {
        (&self).into()
    }
}
impl Into<f32> for &Decimal<u32> {
    fn into(self) -> f32 {
        const X: f32 = 1.0 / (u32::MAX as f32);
        (self.0 as f32) * X
    }
}
impl From<f32> for Decimal<u32> {
    fn from(val: f32) -> Self {
        const X: f32 = u32::MAX as f32;
        Decimal(((val - val.floor()).fract() * X) as u32)
    }
}
impl From<f64> for Decimal<u32> {
    fn from(val: f64) -> Self {
        const X: f64 = u32::MAX as f64;
        Decimal(((val - val.floor()).fract() * X) as u32)
    }
}
impl Display for Decimal<u32> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v: f64 = (*self).into();
        v.fmt(f)
    }
}

// ヘルパー関数たち

/// k < 2*N - 1
pub fn convolution<T, S, const N: usize>(l: &[T; N], r: &[S; N], k: usize) -> T
where
    T: MulAdd<S, Output = T> + Zero + Copy,
    S: Copy,
{
    let l_lim = k.checked_sub(N - 1).unwrap_or(0);
    let r_lim = k.min(N - 1);
    (l_lim..=r_lim).fold(T::zero(), |t, j| unsafe {
        (*l.get_unchecked(k - j)).mul_add(*r.get_unchecked(j), t)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polynomial_new() {
        let _interger_pol = pol!([2, 3, 4, 5]);
        let _float_pol = pol!([3.2, 4.5, 5.6, 7.8]);
        let _decimal_pol = pol!([Decimal(2_u32), Decimal(5_u32)]);
    }
    #[test]
    fn polynomial_add() {
        let l_integer = pol!([2, 3, 4, 5]);
        let r_integer = pol!([4, 5, 6, 7]);

        assert!((l_integer + r_integer).0 == [6, 8, 10, 12]);

        let l_dec = pol!([torus!(0.5), torus!(0.75)]);
        let r_dec = pol!([torus!(0.75), torus!(0.5)]);

        let res = (l_dec + r_dec).0;
        assert!(torus_range_eq(res[0], torus!(0.25), 1e-9));
        assert!(torus_range_eq(res[1], torus!(0.25), 1e-9));
    }
    #[test]
    fn polynomial_schalar() {
        let integer = pol!([2, 3, 4, 5]);

        assert!((integer * 3).0 == [6, 9, 12, 15]);

        let dec = pol!([torus!(0.5), torus!(0.75)]);
        let res = (dec * 3).0;
        assert!(torus_range_eq(res[0], torus!(0.5), 1e-9));
        assert!(torus_range_eq(res[1], torus!(0.25), 1e-9));
    }
    #[test]
    fn polynomial_cross() {
        // i32 * i32
        let l_f = pol!([2, 3, 4]);
        let r_i = pol!([4, 5, 6]);

        assert_eq!((l_f.cross(&r_i)).0, [-30, -2, 43]);

        // decimal * i32
        let acc: f32 = 1e-6;
        {
            let l_d = pol!([torus!(0.5), torus!(0.75)]);
            let r_i = pol!([2, 3]);

            let res = l_d.cross(&r_i);
            assert!(torus_range_eq(res.coef_(0), torus!(0.75), acc));
            assert!(torus_range_eq(res.coef_(1), torus!(0.0), acc));
        }
        {
            let l = pol!([torus!(0.5)]);
            let r = pol!([1]);
            let res = l.cross(&r);
            assert!(
                torus_range_eq(res.coef_(0), l.coef_(0), acc),
                "1をかけても変わらん。part1"
            );
        }
        {
            let l = pol!([torus!(0.25), torus!(0.5)]);
            let r = pol!([1, 0]);
            let res = l.cross(&r);
            assert!(
                torus_range_eq(res.coef_(0), l.coef_(0), acc),
                "1をかけても変わらん。part2"
            );
            assert!(
                torus_range_eq(res.coef_(1), l.coef_(1), acc),
                "1をかけても変わらん。part2"
            );
        }
        {
            let l = pol!([torus!(0.5), torus!(0.25), torus!(0.125)]);
            let r = pol!([1, 0, 0]);
            let res = l.cross(&r);
            assert!(
                torus_range_eq(res.coef_(0), l.coef_(0), acc),
                "1をかけても変わらん。part3"
            );
            assert!(
                torus_range_eq(res.coef_(1), l.coef_(1), acc),
                "1をかけても変わらん。part3"
            );
            assert!(
                torus_range_eq(res.coef_(2), l.coef_(2), acc),
                "1をかけても変わらん。part3"
            );
        }
        {
            let l = pol!([torus!(0.25)]);
            let r = pol!([-1]);
            let res = l.cross(&r);
            assert!(
                torus_range_eq(res.coef_(0), torus!(0.75), acc),
                "-1をかけたら反転"
            );
        }
        {
            let pol_i32 = pol!([1, -1, 1]);
            let pol_torus = pol!([torus!(0.5), torus!(0.25), torus!(0.125)]);
            let res = pol_torus.cross(&pol_i32);
            assert!(
                torus_range_eq(res.coef_(0), torus!(3.0 / 8.0), acc),
                "ノーマル 0"
            );
            assert!(
                torus_range_eq(res.coef_(1), torus!(-3.0 / 8.0), acc),
                "ノーマル 1"
            );
            assert!(
                torus_range_eq(res.coef_(2), torus!(3.0 / 8.0), acc),
                "ノーマル 2"
            );
        }
    }
    #[test]
    fn polynomial_mul_add() {
        let l_f = pol!([2, 3, 4]);
        let r_i = pol!([4, 5, 6]);
        let a_i = pol!([1, 1, 1]);

        assert_eq!((&l_f).mul_add(&r_i, a_i), pol!([-29, -1, 44]));
        assert_eq!(l_f.mul_add(&r_i, a_i), pol!([-29, -1, 44]));

        // decimal * i32
        let acc: f32 = 1e-6;
        {
            let l_d = pol!([torus!(0.5), torus!(0.75)]);
            let r_i = pol!([2, 3]);
            let a_d = pol!([torus!(0.125), torus!(0.25)]);

            let res = l_d.mul_add(&r_i, a_d);
            assert!(torus_range_eq(res.coef_(0), torus!(0.875), acc));
            assert!(torus_range_eq(res.coef_(1), torus!(0.25), acc));
        }
    }
    #[test]
    fn polynomial_decomposition() {
        let pol = pol!([Decimal(0x8000_0000_u32)]);
        let res = pol.decomposition_i32::<7>(4);
        assert_eq!(
            res,
            {
                let coef = pol.coef_(0);
                let decomp = coef.decomposition_i32::<7>(4);
                mem::array_create_enumerate(|i| pol!([decomp[i]]))
            },
            "要素数1のPolynomialを展開"
        );

        let pol = pol!([
            Decimal(0x0000_0001_u32), /*[0,1]*/
            Decimal(0x0002_8000_u32)  /*[3,-32768]*/
        ]);
        let res = pol.decomposition_i32::<2>(16);
        assert_eq!(
            res,
            [pol!([0, 3]), pol!([1, -32768])],
            "要素数2のPolynomialを展開"
        );

        let pol = pol!([Decimal(0b000001_000010_000011_100000_000000_00u32)]);
        let res = pol.decomposition_i32::<3>(6);
        assert_eq!(res, [pol!([1]), pol!([2]), pol!([4])], "パート３");
    }
    #[test]
    fn polynomial_rotate() {
        let pol = pol!([1, 2, 3, 4, 5]);

        assert_eq!(pol.rotate(1), pol!([-5, 1, 2, 3, 4]));
        assert_eq!(pol.rotate(3), pol!([-3, -4, -5, 1, 2]));
        assert_eq!(pol.rotate(-1), pol!([2, 3, 4, 5, -1]));
        assert_eq!(pol.rotate(-3), pol!([4, 5, -1, -2, -3]));
        assert_eq!(pol.rotate(10), pol);
    }
    #[test]
    fn polynomial_fft_cross() {
        /*let acc = 1e-12;

        let l = pol!([1.0_f64, 3.0]);
        let r = pol!([2.0_f64, 3.0]);
        let expect = pol!([-7.0, 9.0]);
        let res = l.fft_cross(&r);
        pol_range_eq(&res, &expect, acc);

        let l = pol!([1.0_f64; 6]);
        let r = pol!([4.0_f64; 6]);
        let expect = l.cross(&r);
        let res = l.fft_cross(&r);
        pol_range_eq(&res, &expect, acc);

        let l = pol!([torus!(0.5), torus!(0.25)]);
        let r = pol!([3, 2]);
        let expect = l.cross(&r);
        let res = l.fft_cross(&r);
        assert!(torus_range_eq(res.coef_(0), expect.coef_(0), 1e-6));
        assert!(torus_range_eq(res.coef_(1), expect.coef_(1), 1e-6));

        let l = pol!([torus!(0.5), torus!(0.25)]);
        let r = pol!([Binary::Zero, Binary::One]);
        let expect = l.cross(&r);
        let res = l.fft_cross(&r);
        assert!(torus_range_eq(res.coef_(0), expect.coef_(0), 1e-6));
        assert!(torus_range_eq(res.coef_(1), expect.coef_(1), 1e-6));*/

        let mut unift = ModDistribution::uniform();
        let mut unifb = BinaryDistribution::uniform();
        const N: usize = 1024;
        for _ in 0..10 {
            let l = pol!(unift.gen_n::<N>());
            let r = pol!(unifb.gen_n::<N>());

            let result = l.fft_cross(&r);
            let expect = l.cross(&r);
            for i in 0..N {
                assert!(
                    torus_range_eq(result.coef_(i), expect.coef_(i), 1e-6),
                    "fft_cross[i] = {:?},expect[i] = {:?}",
                    result.coefs()[i],
                    expect.coefs()[i]
                );
            }
        }
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
            let Decimal(res) = torus!(f);
            assert_eq!(res, respect, "test for {}", f);
        };

        test(0.5, 1 << (u32::BITS - 1));
        test(0.25, 1 << (u32::BITS - 2));
        test(0.125, 1 << (u32::BITS - 3));
        test(-0.5, 1 << (u32::BITS - 1));
        test(-0.25, (1 << (u32::BITS - 2)) + (1 << (u32::BITS - 1)));
    }
    #[test]
    fn decimal_from_f64() {
        let test = |f: f64, expect: u32| {
            let Decimal(res) = torus!(f);
            assert!(range_eq(res, expect, 8), "test for {}", f);
        };

        test(0.5, 1 << (u32::BITS - 1));
        test(0.25, 1 << (u32::BITS - 2));
        test(0.125, 1 << (u32::BITS - 3));
        test(-0.5, 1 << (u32::BITS - 1));
        test(-0.25, (1 << (u32::BITS - 2)) + (1 << (u32::BITS - 1)));
    }

    #[test]
    fn decimal_into_f32() {
        let test = |f: f32, g: f32| {
            let res: f32 = torus!(f).into();
            assert!((res - g).abs() < f32::EPSILON, "test for {}", f);
        };

        test(0.5, 0.5);
        test(0.25, 0.25);
        test(-0.25, 0.75);
        test(0.4, 0.4);
        test(0.123, 0.123);
        test(1e-6, 1e-6);
        test(1e-10, 0.0);
        test(3.1, 0.1);
    }
    #[test]
    fn decimal_into_f64() {
        let test = |f: f64, g: f64| {
            let res: f64 = torus!(f).into();
            assert!((res - g).abs() < 1e-9, "test for {}", f);
        };

        test(0.5, 0.5);
        test(0.25, 0.25);
        test(-0.25, 0.75);
        test(0.4, 0.4);
        test(0.123, 0.123);
        test(1e-6, 1e-6);
        test(1e-8, 1e-8);
        test(1e-10, 0.0);
        test(3.1, 0.1);
    }
    #[test]
    fn decimal_add() {
        let acc = 1e-6;
        let test = |x: f32, y: f32, z: f32| {
            let dx = torus!(x);
            let dy = torus!(y);
            let result = dx + dy;
            let expect = torus!(z);

            assert!(
                torus_range_eq(result, expect, acc),
                "test for {}+{} == {} ?\n result={},respect={}",
                x,
                y,
                z,
                result,
                expect,
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
        let acc: f32 = 1e-6; // これくらいの精度は出る。有効数字6桁くらい

        let test_u32 = |x: f32, y: u32, z: f32| {
            let dx = torus!(x);
            let result = dx * y;
            let respect = torus!(z);

            assert!(
                torus_range_eq(result, respect, acc),
                "test_u32 for {}*{} == {} ? result={},respect={}",
                x,
                y,
                z,
                result,
                respect
            );
        };

        test_u32(0.5, 1, 0.5);
        test_u32(0.25, 2, 0.5);
        test_u32(0.5, 2, 0.0);
        test_u32(0.75, 4, 0.0);
        test_u32(0.4, 3, 0.2);
        test_u32(0.67, 2, 0.34);
        test_u32(0.524, 5, 0.62);
        test_u32(0.24, 0, 0.0);

        let test_i32 = |x: f32, y: i32, z: f32| {
            let dx = torus!(x);
            let result = dx * y;
            let respect = torus!(z);

            assert!(
                torus_range_eq(result, respect, acc),
                "test_i32 for {}*{} == {} ? result={},respect={}",
                x,
                y,
                z,
                result,
                respect
            );
        };
        test_i32(0.5, 2, 0.0);
        test_i32(0.25, -2, 0.5);
        test_i32(0.125, -3, 0.625);
        test_i32(0.24, 0, 0.0);
        test_i32(0.23, -1, 0.77);

        let test_binary = |x: f32, y: Binary, z: f32| {
            let dx = torus!(x);
            let result = dx * y;
            let respect = torus!(z);

            assert!(
                torus_range_eq(result, respect, acc),
                "test_binary for {}*{} == {} ? result={},respect={}",
                x,
                y,
                z,
                result,
                respect
            );
        };
        test_binary(0.5, Binary::One, 0.5);
        test_binary(0.25, Binary::Zero, 0.0);
    }
    #[test]
    fn decimal_neg() {
        let test = |x: f32| {
            let acc: f32 = 1e-6;

            let dec = torus!(x);
            let expect = torus!(-x);
            let result = -dec;

            assert!(
                torus_range_eq(result, expect, acc),
                "result={:?},expect={:?}",
                result,
                expect,
            );
        };

        test(0.5);
        test(-0.25);
        test(0.125);
        test(0.4);
    }
    #[test]
    fn decimal_sub() {
        let test = |x: f32, y: f32, respect: f32| {
            let acc: f32 = 1e-6;

            let x_ = torus!(x);
            let y_ = torus!(y);
            let expect = torus!(respect);
            let result = x_ - y_;

            assert!(
                torus_range_eq(result, expect, acc),
                "result={:?},expect={:?}",
                result,
                expect,
            );
        };

        test(0.5, 0.25, 0.25);
        test(-0.25, 0.25, 0.5);
        test(0.125, 0.625, 0.5);
        test(0.4, 0.2, 0.2);

        let test = |x: f32, y: f32, z: f32, expect: f32| {
            let acc = 1e-6;

            let expect = torus!(expect);
            let result = torus!(x) - (torus!(y) + torus!(z));

            assert!(
                torus_range_eq(result, expect, acc),
                "result={:?},expect={:?}",
                result,
                expect,
            );
        };

        test(0.5, 0.25, 0.125, 0.125);
        test(0.23, 0.4, 0.83, 0.0);
        test(0.4, 0.7, 0.4, 0.3);
    }
    #[test]
    fn decimal_decomposition() {
        let dec = Decimal(0x80000000_u32); // 0.5
        let res = dec.decomposition_u32::<32>(1);
        assert_eq!(
            res,
            [
                1_u32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
            ],
            "test1_u32"
        );
        let res = dec.decomposition_i32::<32>(1);
        assert_eq!(
            res,
            [
                -1_i32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
            ],
            "test1_i32"
        );

        let res = dec.decomposition_i32::<8>(4);
        assert_eq!(
            res,
            [-8_i32, 0, 0, 0, 0, 0, 0, 0],
            "test2:[-2^bits/2,2^bits/2)で表現"
        );
        let res = dec.decomposition_i32::<7>(4);
        assert_eq!(
            res,
            [-8_i32, 0, 0, 0, 0, 0, 0],
            "test3:32に足らなくてもいい"
        );

        let dec = Decimal(0x8000_0001_u32);
        let res = dec.decomposition_u32::<31>(1);
        assert_eq!(
            res,
            [
                1_u32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1 /*ここはもとの数では0だけど四捨五入で-1*/
            ],
            "test3_u32: 繰り上がりがある。丸めるから"
        );
        let res = dec.decomposition_i32::<31>(1);
        assert_eq!(
            res,
            [
                0_i32, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1 /*ここはもとの数では0だけど四捨五入で-1*/
            ],
            "test3_i32: 繰り上がりがある。丸めるから"
        );

        let dec = Decimal(0b000001_000010_000011_000000_000000_00u32);
        let res = dec.decomposition_i32::<3>(6);
        assert_eq!(res, [1, 2, 3], "test4: 本番と同じ使い方。繰り上がりなし");

        let dec = Decimal(0b000001_000010_000011_100000_000000_00u32);
        let res = dec.decomposition_i32::<3>(6);
        assert_eq!(res, [1, 2, 4], "test4: 本番と同じ使い方。繰り上がりあり");

        let dec = Decimal(0b011111_100000_100000_000000_100000_00u32);
        let res = dec.decomposition_i32::<3>(6);
        assert_eq!(res, [-32, -31, -32], "test5: 繰り上がりも桁上がりもある");
    }

    #[bench]
    fn bench_decimal_to_f32(b: &mut test::Bencher) {
        let x = Decimal(0x8000_0000_u32);
        b.iter(|| {
            let _: f32 = x.into();
        });
    }

    #[allow(dead_code)]
    fn range_eq<T: Sub<Output = T> + PartialOrd>(result: T, expect: T, acc: T) -> bool {
        let diff: T = if result > expect {
            result - expect
        } else {
            expect - result
        };
        acc > diff
    }
    fn torus_range_eq(result: Torus32, expect: Torus32, acc: f32) -> bool {
        let result: f32 = result.into();
        let expect: f32 = expect.into();
        (result - expect).abs().min((result + expect - 1.0).abs()) < acc
    }
    #[allow(dead_code)]
    fn pol_range_eq<T, const N: usize>(result: &Polynomial<T, N>, expect: &Polynomial<T, N>, acc: T)
    where
        T: PartialOrd + Sub<Output = T> + Copy + std::fmt::Debug,
    {
        for i in 0..N {
            assert!(
                range_eq(result.coef_(i), expect.coef_(i), acc),
                "result={:?}, respect={:?}",
                result,
                expect
            );
        }
    }
}
