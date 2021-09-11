use std::mem::MaybeUninit;
use std::ops::Add;
use std::ops::Sub;
use std::os::raw::c_double;
use std::os::raw::c_int;
use std::os::raw::c_uint;

use num::Zero;

use crate::math::Polynomial;
use crate::math::Torus32;
use crate::mem;
use crate::pol;

pub enum SpqliosImpl {}

extern "C" {
    fn Spqlios_new(N: c_int) -> *mut SpqliosImpl;
    fn Spqlios_destructor(spqlios: *mut SpqliosImpl);
    fn Spqlios_ifft(spqlios: *mut SpqliosImpl, res: *mut c_double, src: *const c_double);
    fn Spqlios_ifft_u32(spqlios: *mut SpqliosImpl, res: *mut c_double, src: *const c_uint);
    fn Spqlios_ifft_i32(spqlios: *mut SpqliosImpl, res: *mut c_double, src: *const c_int);
    fn Spqlios_fft(spqlios: *mut SpqliosImpl, res: *mut c_double, src: *const c_double);
    fn Spqlios_fft_u32(spqlios: *mut SpqliosImpl, res: *mut c_uint, src: *const c_double);
    fn Spqlios_poly_mul(
        spqlios: *mut SpqliosImpl,
        res: *mut c_uint,
        src_a: *const c_uint,
        src_b: *const c_uint,
    );
}

pub struct Spqlios {
    raw: *mut SpqliosImpl,
    n: usize,
}

impl Spqlios {
    pub fn new(n: usize) -> Self {
        debug_assert!(n >= 16);
        debug_assert!(n.is_power_of_two());

        unsafe {
            Spqlios {
                raw: Spqlios_new(n as i32),
                n,
            }
        }
    }

    pub fn ifft<const N: usize>(&mut self, input: &[f64; N]) -> FrrSeries<N> {
        debug_assert!(self.n == N, "spqlios: self.n={},N={}", self.n, N);

        let mut res: [MaybeUninit<f64>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe {
            Spqlios_ifft(
                self.raw,
                res.as_mut_ptr() as *mut _,
                input.as_ptr() as *const _,
            );
        }
        FrrSeries(crate::mem::transmute::<_, [f64; N]>(res))
    }

    pub fn ifft_torus<const N: usize>(&mut self, input: &[Torus32; N]) -> FrrSeries<N> {
        debug_assert!(self.n == N, "spqlios: self.n={},N={}", self.n, N);

        let mut res: [MaybeUninit<f64>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe {
            Spqlios_ifft_u32(
                self.raw,
                res.as_mut_ptr() as *mut _,
                input.as_ptr() as *const _,
            );
        }
        FrrSeries(crate::mem::transmute::<_, [f64; N]>(res))
    }

    pub fn ifft_int<const N: usize>(&mut self, input: &[i32; N]) -> FrrSeries<N> {
        debug_assert!(self.n == N, "spqlios: self.n={},N={}", self.n, N);

        let mut res: [MaybeUninit<f64>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe {
            Spqlios_ifft_i32(
                self.raw,
                res.as_mut_ptr() as *mut _,
                input.as_ptr() as *const _,
            );
        }
        FrrSeries(crate::mem::transmute::<_, [f64; N]>(res))
    }

    pub fn fft<const N: usize>(&mut self, input: &FrrSeries<N>) -> [f64;N] {
        debug_assert!(self.n == N, "spqlios: self.n={},N={}", self.n, N);

        let mut res: [MaybeUninit<f64>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe {
            Spqlios_fft(
                self.raw,
                res.as_mut_ptr() as *mut _,
                input.0.as_ptr() as *const _,
            );
        }
        crate::mem::transmute::<_, [f64; N]>(res)
    }

    pub fn fft_torus<const N: usize>(&mut self, input: &FrrSeries<N>) -> [Torus32; N] {
        debug_assert!(self.n == N, "spqlios: self.n={},N={}", self.n, N);

        let mut res: [MaybeUninit<Torus32>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe {
            Spqlios_fft_u32(
                self.raw,
                res.as_mut_ptr() as *mut _,
                input.0.as_ptr() as *const _,
            );
        }
        crate::mem::transmute::<_, [Torus32; N]>(res)
    }

    pub fn poly_mul<const N: usize>(&mut self, a: &[Torus32; N], b: &[Torus32; N]) -> [Torus32; N] {
        debug_assert!(self.n == N, "spqlios: self.n={},N={}", self.n, N);

        let mut res: [MaybeUninit<Torus32>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        unsafe {
            Spqlios_poly_mul(
                self.raw,
                res.as_mut_ptr() as *mut _,
                a.as_ptr() as *const _,
                b.as_ptr() as *const _,
            );
        }

        crate::mem::transmute::<_, [Torus32; N]>(res)
    }
}

impl Drop for Spqlios {
    fn drop(&mut self) {
        unsafe {
            Spqlios_destructor(self.raw);
        }
    }
}

pub struct FrrSeries<const N: usize>([f64; N]);
impl<const N: usize> Add<&Self> for FrrSeries<N> {
    type Output = Self;
    fn add(mut self, rhs: &Self) -> Self::Output {
        self.0.iter_mut().zip(rhs.0).for_each(|(a, b)| *a += b);
        self
    }
}
impl<const N: usize> Add for FrrSeries<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}
impl<const N: usize> Sub<&Self> for FrrSeries<N> {
    type Output = Self;
    fn sub(mut self, rhs: &Self) -> Self::Output {
        self.0.iter_mut().zip(rhs.0).for_each(|(a, b)| *a -= b);
        self
    }
}
impl<const N: usize> Sub for FrrSeries<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}
impl<const N: usize> Zero for FrrSeries<N> {
    fn zero() -> Self {
        FrrSeries([0.0_f64; N])
    }
    fn is_zero(&self) -> bool {
        self.0.iter().all(|a| a.is_zero())
    }
}
impl<const N: usize> FrrSeries<N> {
    pub fn hadamard(&self, rhs: &Self) -> Self {
        let mut res: [MaybeUninit<f64>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        for i in 0..N / 2 {
            let ii = self.0[i + N / 2] * rhs.0[i + N / 2];
            let rr = self.0[i] * rhs.0[i];
            let ri = self.0[i] * rhs.0[i + N / 2];
            let ir = self.0[i + N / 2] * rhs.0[i];
            res[i] = MaybeUninit::new(rr - ii);
            res[i + N / 2] = MaybeUninit::new(ir + ri);
        }
        FrrSeries(mem::transmute::<_, [f64; N]>(res))
    }
    pub fn culc_poly_torus(&self, spq:&mut Spqlios) -> Polynomial<Torus32,N> {
        pol!(spq.fft_torus(&self))
    }
    pub fn culc_poly(&self, spq:&mut Spqlios) -> Polynomial<f64,N> {
        pol!(spq.fft(&self))
    }
}


#[cfg(test)]
mod tests {
    use crate::math::Torus32;
    use num::Zero;

    use super::Spqlios;

    fn very_close(a:Torus32,b:Torus32) -> bool{
        let a_:f64 = a.into();
        let b_:f64 = b.into();
        (a_ - b_).abs() < 1000.0
    }
    #[test]
    fn fft_test() {
        let mut spq = Spqlios::new(16);

        let pol0: [Torus32; 16] = {
            let mut tmp = [Torus32::zero(); 16];
            tmp[1] = Torus32::from_bits(1);
            tmp[2] = Torus32::from_bits(1);
            tmp
        };
        let pol0_if_f = {
            let pol_if = spq.ifft_torus(&pol0);
            spq.fft_torus(&pol_if)
        };
        assert_eq!(pol0_if_f, pol0, "fft_test: step 1");

        let pol1 = pol0;
        let res = spq.poly_mul(&pol0, &pol1);
        let expect= {
            let mut tmp: [Torus32; 16] = [Torus32::zero(); 16];
            tmp[2] = Torus32::from_bits(1);
            tmp[3] = Torus32::from_bits(2);
            tmp[4] = Torus32::from_bits(1);
            tmp
        };
        for (&r,e) in res.iter().zip(expect) {
            assert!(very_close(r, e),"fft test: step 2 res={:?},expect={:?}",res,expect);
        }
    }
}
