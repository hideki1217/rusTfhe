# rusTfhe
Secret calculation library based on tfhe,and written in pure Rust.

# crates
- nander: console app to culc logical expression with homNand
- hom_nand: library of tfhe and other crypto methods
- utils: utility library including math, mem, and macros

# build
- cargo 1.56.0-nightly
```
git clone https://github.com/hideki1217/rusTfhe
cd rusTfhe
cargo build --release
cargo run --release 
```

# run tfhe bench
```
git clone https://github.com/hideki1217/rusTfhe
cd rusTfhe
cargo run --release --exmaple homnand-bench
```



