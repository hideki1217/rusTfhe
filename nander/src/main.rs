use hom_nand::{
    digest::Cryptor,
    tfhe::{TFHEHelper, TFHE},
    tlwe::{TLWEHelper, TLWE},
};
use nander::{eval_logic_expr, parse_logic_expr};
use std::io::{self, BufRead, Write};
use utils::math::{Binary, BinaryDistribution, Random};

fn main() -> io::Result<()> {
    println!("Hello nander!!");
    println!("[Rule]1:true,0:false,&:and,$:nand,!:not,|:or,^:xor");
    println!("[Example]");
    println!("- 1&1 => 1");
    println!("- !(1|0)$0 => 1");
    println!("- 1&1$0 => (1&1)$0");

    const TLWE_N: usize = TLWEHelper::N;
    const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
    let mut unif = BinaryDistribution::uniform();
    let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
    let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();
    let pros = TFHE::new(s_key_tlwelv0, s_key_tlwelv1);

    let print_sufix = || {
        print!("nander>");
        io::stdout().flush().unwrap();
    };
    print_sufix();
    for line in std::io::BufReader::new(io::stdin()).lines() {
        match line {
            Ok(s) => {
                let exp = parse_logic_expr(&s);
                let start = std::time::Instant::now();
                let z_ = eval_logic_expr(&pros, exp);
                let time_ms = start.elapsed().as_millis();

                let z: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, z_);

                println!("> {}", z);
                println!("culc time = {} milli sec", time_ms);
            }
            Err(error) => {
                println!("{}", error);
            }
        }
        print_sufix();
    }
    Ok(())
}
