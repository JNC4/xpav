//! Benchmarks for scanner performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn webshell_scan_benchmark(c: &mut Criterion) {
    // Placeholder - will be implemented in Phase 5.2
    c.bench_function("webshell_scan_clean", |b| {
        b.iter(|| {
            black_box("<?php echo 'Hello World'; ?>")
        })
    });
}

fn entropy_calculation_benchmark(c: &mut Criterion) {
    let data = vec![0u8; 4096];
    c.bench_function("entropy_4kb", |b| {
        b.iter(|| {
            black_box(&data)
        })
    });
}

criterion_group!(
    benches,
    webshell_scan_benchmark,
    entropy_calculation_benchmark,
);
criterion_main!(benches);
