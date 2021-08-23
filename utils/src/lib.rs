extern crate rustfft;

pub mod macros;
pub mod math;
pub mod mem;

#[cfg(test)]
mod tests {
    use super::*;
    use math::Binary;
    #[test]
    fn playground() {
        let x = Binary::One;
        println!("{}", std::mem::size_of_val(&x));
        let y = Binary::Zero;
        let z = x as u8 + y as u8;
        println!("{}", z);
    }
}
