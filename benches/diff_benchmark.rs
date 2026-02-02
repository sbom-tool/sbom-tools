//! Benchmarks for the diff engine.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn benchmark_placeholder(c: &mut Criterion) {
    c.bench_function("placeholder", |b| {
        b.iter(|| {
            black_box(1 + 1);
        })
    });
}

criterion_group!(benches, benchmark_placeholder);
criterion_main!(benches);
