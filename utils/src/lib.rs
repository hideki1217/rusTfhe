pub mod macros;
pub mod math;
pub mod mem;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn playground() {
        let x = math::Binary::One;
        println!("{}", std::mem::size_of_val(&x));
        let y = math::Binary::Zero;
        let z = x as u8 + y as u8;
        println!("{}", z);
    }
}
