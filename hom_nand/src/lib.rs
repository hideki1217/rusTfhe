#![feature(const_generics)]
#![feature(const_evaluatable_checked)]
#![feature(test)]
extern crate test;
extern crate debug_print;

extern crate utils;

pub mod digest;
pub mod tlwe;
pub mod trgsw;
pub mod trlwe;
pub mod tfhe;


#[cfg(test)]
mod tests {
    use test::Bencher;

    #[test]
    fn playground() {
        let x = [0,1,2,3,4,5,6,7,8,9];
        x.iter().for_each(|f|println!("{}",f));

        x.iter().take(5).for_each(|f|println!("{}",f));
        x.iter().skip(4).for_each(|f|println!("{}",f));
    }

    #[bench]
    fn f_0(g:&mut Bencher){
        g.iter(|| {
            let x = test::black_box(1.5_f32);
            x%1.0
        });
    }

    #[bench]
    fn f_1(g:&mut Bencher){
        g.iter(|| {
        let x = test::black_box(1.5_f32);
        (x - x.floor()).fract()
        })
    }
}
