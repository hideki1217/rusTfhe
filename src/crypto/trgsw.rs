use super::digest::{Crypto, Encrypted};

pub struct TRGSW;
impl TRGSW {
    const Bgbit: u32 = 6;
    const Bg: usize = 2_i32.pow(TRGSW::Bgbit) as usize;
    const l: u32 = 3;
    pub fn new() -> Self {
        TRGSW
    }
}
