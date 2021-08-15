use array_macro::array;
use num::ToPrimitive;

use super::digest::{Crypto, Encrypted};
use super::trlwe::TRLWE;
use math_utils::{Binary, Polynomial, Torus};
use math_utils::{torus,pol};

pub struct TRGSW;
impl TRGSW {
    const BGBIT: u32 = 6;
    const BG: usize = 2_i32.pow(TRGSW::BGBIT) as usize;
    const L: usize = 3;
    pub fn new() -> Self {
        TRGSW
    }
    pub fn binary_pol2u32_pol<const N: usize>(pol: Polynomial<Binary, N>) -> Polynomial<u32, N> {
        pol!(array![ i => pol.coef_(i).to_u32().unwrap() ;N])
    }
    fn u32_pol2binary_pol<const N: usize>(pol: Polynomial<u32, N>) -> Polynomial<Binary, N> {
        pol!(array![ i => Binary::from(pol.coef_(i)) ; N])
    }
}
impl<const N: usize> Crypto<Polynomial<u32, N>> for TRGSW {
    type SecretKey = Polynomial<Torus, N>;
    type Cipher = [Polynomial<Torus, N>; 2 * TRGSW::L];
    type PublicKey = [Polynomial<Torus, N>; 2 * TRGSW::L];

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<u32, N>,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        todo!()
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Polynomial<u32, N> {
        todo!()
    }
}
impl<const N: usize> Crypto<Polynomial<Binary, N>> for TRGSW {
    type SecretKey = Polynomial<Torus, N>;
    type Cipher = [Polynomial<Torus, N>; 2 * TRGSW::L];
    type PublicKey = [Polynomial<Torus, N>; 2 * TRGSW::L];

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<Binary, N>,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        self.encrypto(s_key, TRGSW::binary_pol2u32_pol(item))
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Polynomial<Binary, N> {
        TRGSW::u32_pol2binary_pol(self.decrypto(s_key, p_key, cipher))
    }
}
