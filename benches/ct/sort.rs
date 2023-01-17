use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use raw_ipa::test_fixture::sort;
use tokio::runtime::Builder;

pub fn criterion_benchmark(c: &mut Criterion) {
    let rt = Builder::new_multi_thread()
        .worker_threads(3)
        .thread_name("helper-worker")
        .enable_time()
        .build()
        .expect("Creating runtime failed");

    let mut group = c.benchmark_group("arithmetic");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for batchsize in [100usize] {
        for num_multi_bits in [1u32, 2, 3, 4, 5] {
            group.throughput(Throughput::Elements((batchsize as u32 * num_multi_bits) as u64));
            group.bench_with_input(
                BenchmarkId::new("sort", format!("{batchsize}:{num_multi_bits}")),
                &(batchsize, num_multi_bits),
                |b, &(batchsize, num_multi_bits)| {
                    b.to_async(&rt)
                        .iter(|| sort::sort(black_box(batchsize), black_box(num_multi_bits)));
                },
            );
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
