// 時間計測のコードを挿入するマクロ
#[macro_export]
macro_rules! timeit {
    ($label: expr, $code: expr) => {{
        let start = time::Instant::now();
        let ret = $code;
        let end_ms = start.elapsed().as_micros();

        println!("{}: {} micro-seconds", $label, end_ms);

        ret
    }};
}
