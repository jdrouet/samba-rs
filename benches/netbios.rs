use criterion::{Criterion, criterion_group, criterion_main};

fn parsing_valid() {
    samba_rs::entities::netbios::Header::parse(&[0u8, 0, 0, 64]).unwrap();
}

fn parsing_invalid() {
    samba_rs::entities::netbios::Header::parse(&[1u8, 0, 0, 64]).unwrap_err();
}

fn parsing_small() {
    samba_rs::entities::netbios::Header::parse(&[1, 2, 3]).unwrap_err();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parsing valid", |b| b.iter(parsing_valid));
    c.bench_function("parsing invalid", |b| b.iter(parsing_invalid));
    c.bench_function("parsing small", |b| b.iter(parsing_small));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
