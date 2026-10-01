//! This benchmark measures process and thread tracker operations.
//!
//! Criterion can save a baseline with `--save-baseline NAME` and compare a
//! later build with `--baseline NAME`.

use std::{convert::Infallible, hint::black_box};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use vmi_core::{
    Va,
    os::{ProcessObject, ThreadObject},
};
use vmi_utils::tracker::Tracker;

/// The benchmarks use this many process and thread pairs for working-set cases.
const WORKING_SET_SIZE: usize = 1024;

/// Builds a process object for a benchmark index.
fn process(index: usize) -> ProcessObject {
    ProcessObject(Va(0x1000 + (index as u64 * 0x2000)))
}

/// Builds a thread object for a benchmark index.
fn thread(index: usize) -> ThreadObject {
    ThreadObject(Va(0x2000 + (index as u64 * 0x2000)))
}

/// Builds a tracker containing `count` process and thread pairs.
fn populated_tracker(count: usize) -> Tracker<u64, u64> {
    let mut tracker = Tracker::default();

    for index in 0..count {
        tracker.insert(process(index), thread(index), index as u64, index as u64);
    }

    tracker
}

/// Panics if an existing process unexpectedly requires initialization.
fn existing_process() -> Result<u64, Infallible> {
    unreachable!("existing process initializer must not run")
}

/// Panics if an existing thread unexpectedly requires initialization.
fn existing_thread() -> Result<u64, Infallible> {
    unreachable!("existing thread initializer must not run")
}

/// Measures repeated lookup of one active process and thread pair.
fn bench_hot_hit_single(criterion: &mut Criterion) {
    let process_object = process(0);
    let thread_object = thread(0);
    let mut tracker = populated_tracker(1);

    criterion.benchmark_group("process_tracker").bench_function(
        "try_get_or_insert/hot_hit_single",
        |bencher| {
            bencher.iter(|| {
                let (process_value, thread_value) = tracker
                    .try_get_or_insert(
                        black_box(process_object),
                        black_box(thread_object),
                        existing_process,
                        existing_thread,
                    )
                    .unwrap();

                black_box((*process_value, *thread_value));
            });
        },
    );
}

/// Measures active lookups across the working set.
fn bench_hot_hit_working_set(criterion: &mut Criterion) {
    let pairs = (0..WORKING_SET_SIZE)
        .map(|index| (process(index), thread(index)))
        .collect::<Vec<_>>();
    let mut tracker = populated_tracker(WORKING_SET_SIZE);
    let mut index = 0;

    let mut group = criterion.benchmark_group("process_tracker");
    group.throughput(Throughput::Elements(1));
    group.bench_function("try_get_or_insert/hot_hit_working_set_1024", |bencher| {
        bencher.iter(|| {
            let (process_object, thread_object) = pairs[index];
            index = (index + 1) & (WORKING_SET_SIZE - 1);

            let (process_value, thread_value) = tracker
                .try_get_or_insert(
                    black_box(process_object),
                    black_box(thread_object),
                    existing_process,
                    existing_thread,
                )
                .unwrap();

            black_box((*process_value, *thread_value));
        });
    });
    group.bench_function("get_mut/hot_hit_working_set_1024", |bencher| {
        bencher.iter(|| {
            let (process_object, thread_object) = pairs[index];
            index = (index + 1) & (WORKING_SET_SIZE - 1);

            let (process_value, thread_value) = tracker
                .get_mut(black_box(process_object), black_box(thread_object))
                .unwrap();

            black_box((*process_value, *thread_value));
        });
    });
    group.finish();
}

/// Measures replacement of a retired thread.
fn bench_replace_retired_thread(criterion: &mut Criterion) {
    let process_object = process(0);
    let thread_object = thread(0);

    criterion.benchmark_group("process_tracker").bench_function(
        "try_get_or_insert/replace_retired_thread",
        |bencher| {
            bencher.iter_batched(
                || {
                    let mut tracker = populated_tracker(1);
                    tracker
                        .retire_thread(process_object, thread_object)
                        .unwrap();
                    tracker
                },
                |mut tracker| {
                    let (process_value, thread_value) = tracker
                        .try_get_or_insert(
                            black_box(process_object),
                            black_box(thread_object),
                            existing_process,
                            || Ok::<_, Infallible>(1),
                        )
                        .unwrap();

                    black_box((*process_value, *thread_value));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(
    benches,
    bench_hot_hit_single,
    bench_hot_hit_working_set,
    bench_replace_retired_thread,
);
criterion_main!(benches);
