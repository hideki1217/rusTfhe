use num::Integer;


pub struct Array1<T: Integer,const N:usize> {
    items: [T;N],
}
impl<T: Integer+Copy, const N:usize> Array1<T, N> {
    fn new(items: [T;N] ) -> Self {
        Array1 { items }
    }
    fn dot(&self,rhs: &Array1<T,N>) -> T {
        self.items.iter()
            .zip(rhs.items.iter())
            .map(|(&x,&y)| x*y)
            .fold(T::zero(),|sum, xy| sum + xy)
    }
}
impl<T: Integer+Copy, const N:usize> Default for Array1<T, N> {
    fn default() -> Self {
        Self::new([T::zero();N])
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array1_dot() {
        let x:Array1<u32,3> = Array1::new([3,4,5]);
        let y:Array1<u32,3> = Array1::new([1,2,3]);

        assert!(x.dot(&y) == 26)
    }
}

