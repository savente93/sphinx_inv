use criterion::{Criterion, criterion_group, criterion_main};
use sphinx_inv::parse_objects_inv_file;
use std::path::PathBuf;

fn criterion_benchmark(c: &mut Criterion) {
    let numpy_file_path = PathBuf::from("tests/sphinx_objects/numpy.inv");
    c.bench_function("numpy", |b| {
        b.iter(|| {
            let _ = parse_objects_inv_file(&numpy_file_path);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
