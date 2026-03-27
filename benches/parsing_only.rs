use criterion::{Criterion, criterion_group, criterion_main};
use sphinx_inv::ExternalSphinxRef;
use std::{fs, path::PathBuf};

fn criterion_benchmark(c: &mut Criterion) {
    let path = PathBuf::from("tests/sphinx_objects/giant.inv");

    #[allow(clippy::unwrap_used)]
    let giant_payload: String = fs::read_to_string(path).unwrap();

    c.bench_function("giant_text_parse", |b| {
        b.iter(|| {
            for line in giant_payload.lines() {
                // this is a benchmark so we don't actually care about the result
                let _ = ExternalSphinxRef::try_from(line);
            }
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
