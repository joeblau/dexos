use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crypto::KeyPair;
use loadgen::campaign::{
    ActionHistograms, LatencyHistogram, LoadScenario, OpenLoopScheduler, OperationMix,
    ProtocolAdapter, ProtocolSlot,
};
use loadgen::SessionState;
use types::{AccountId, Ratio};

struct CountingAllocator;
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: this delegates every allocation/deallocation unchanged to the process
// System allocator and only adds a relaxed diagnostic counter. The executable is an
// isolated benchmark, not linked into production binaries.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is passed through unchanged under GlobalAlloc's contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer/layout came from the delegated System allocation.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: pointer/layout came from System and the requested size is forwarded.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn main() {
    const WARM_UP: u64 = 20_000;
    const OPERATIONS: u64 = 1_000_000;
    let scenario = LoadScenario {
        market_ids: vec![1, 2, 3, 4],
        operation_mix: Some(OperationMix {
            new: Ratio::from_raw(550_000),
            cancel: Ratio::from_raw(300_000),
            replace: Ratio::from_raw(150_000),
        }),
        ..LoadScenario::default()
    };
    let mut session = SessionState::with_partition(7, &scenario, "bench", 0, true);
    let adapter = ProtocolAdapter::new(
        AccountId::new(1),
        KeyPair::from_seed(&[7; 32]),
        10_000,
        None,
    );
    let mut slot = ProtocolSlot::new(4096, 4096, 8192);
    let mut queue_delay = LatencyHistogram::new(60_000_000_000);
    let mut request_to_ack = LatencyHistogram::new(60_000_000_000);
    let mut dimension_queue_delay = LatencyHistogram::new(60_000_000_000);
    let mut dimension_request_to_ack = LatencyHistogram::new(60_000_000_000);
    let mut interval_queue_delay = LatencyHistogram::new(60_000_000_000);
    let mut interval_request_to_ack = LatencyHistogram::new(60_000_000_000);
    let mut action_queue_delay = ActionHistograms::new(60_000_000_000);
    let mut action_request_to_ack = ActionHistograms::new(60_000_000_000);
    let mut interval_action_queue_delay = ActionHistograms::new(60_000_000_000);
    let mut interval_action_request_to_ack = ActionHistograms::new(60_000_000_000);
    let mut ignored_rng = loadgen::Lcg::new(0);
    for request_id in 0..WARM_UP {
        let command = session.next_command(&mut ignored_rng, &scenario);
        adapter
            .encode_into_slot(request_id, &command, &mut slot)
            .expect("warm-up slot must be large enough");
        record_runtime_metrics(
            request_id,
            command.kind,
            &mut queue_delay,
            &mut request_to_ack,
            &mut dimension_queue_delay,
            &mut dimension_request_to_ack,
            &mut interval_queue_delay,
            &mut interval_request_to_ack,
            &mut action_queue_delay,
            &mut action_request_to_ack,
            &mut interval_action_queue_delay,
            &mut interval_action_request_to_ack,
        );
        black_box(slot.frame());
    }

    ALLOCATIONS.store(0, Ordering::SeqCst);
    let started = Instant::now();
    let mut encoded_bytes = 0u64;
    let mut scheduled_operations = 0u64;
    let mut scheduler = OpenLoopScheduler::new(0, OPERATIONS, 1, scenario.burst);
    for request_id in 0..OPERATIONS {
        let schedule = scheduler.poll(request_id.saturating_mul(1_000), 1);
        scheduled_operations = scheduled_operations.saturating_add(schedule.emit);
        black_box(schedule);
        let command = session.next_command(&mut ignored_rng, &scenario);
        adapter
            .encode_into_slot(request_id, &command, &mut slot)
            .expect("fixed benchmark slot must be large enough");
        record_runtime_metrics(
            request_id,
            command.kind,
            &mut queue_delay,
            &mut request_to_ack,
            &mut dimension_queue_delay,
            &mut dimension_request_to_ack,
            &mut interval_queue_delay,
            &mut interval_request_to_ack,
            &mut action_queue_delay,
            &mut action_request_to_ack,
            &mut interval_action_queue_delay,
            &mut interval_action_request_to_ack,
        );
        encoded_bytes =
            encoded_bytes.saturating_add(u64::try_from(slot.frame().len()).unwrap_or(u64::MAX));
        black_box(slot.frame());
    }
    let elapsed = started.elapsed();
    let allocations = ALLOCATIONS.load(Ordering::SeqCst);
    let operations_per_second =
        u128::from(OPERATIONS).saturating_mul(1_000_000_000) / elapsed.as_nanos().max(1);
    let bytes_per_operation_milli =
        u128::from(encoded_bytes).saturating_mul(1_000) / u128::from(OPERATIONS);
    let logical_cpus = std::thread::available_parallelism().map_or(0, usize::from);
    println!(
        "hot_path operations={OPERATIONS} scheduled_operations={scheduled_operations} elapsed_ns={} operations_per_second={operations_per_second} encoded_bytes={encoded_bytes} bytes_per_operation_milli={bytes_per_operation_milli} allocations={allocations} allocations_per_operation_millionths={} arch={} os={} logical_cpus={logical_cpus}",
        elapsed.as_nanos(),
        allocations.saturating_mul(1_000_000) / OPERATIONS,
        std::env::consts::ARCH,
        std::env::consts::OS,
    );
    assert_eq!(scheduled_operations, OPERATIONS);
    assert_eq!(
        allocations, 0,
        "steady-state generation/signing/framing/metrics path allocated"
    );

    const REPORT_SNAPSHOTS: u64 = 100;
    ALLOCATIONS.store(0, Ordering::SeqCst);
    for _ in 0..REPORT_SNAPSHOTS {
        let snapshot_histogram = LatencyHistogram::new(60_000_000_000);
        black_box(snapshot_histogram.summary());
    }
    let snapshot_allocations = ALLOCATIONS.load(Ordering::SeqCst);
    println!(
        "report_snapshots={REPORT_SNAPSHOTS} snapshot_allocations={snapshot_allocations} allocations_per_snapshot={}",
        snapshot_allocations / REPORT_SNAPSHOTS
    );
}

#[allow(clippy::too_many_arguments)]
fn record_runtime_metrics(
    value: u64,
    kind: loadgen::CommandKind,
    queue_delay: &mut LatencyHistogram,
    request_to_ack: &mut LatencyHistogram,
    dimension_queue_delay: &mut LatencyHistogram,
    dimension_request_to_ack: &mut LatencyHistogram,
    interval_queue_delay: &mut LatencyHistogram,
    interval_request_to_ack: &mut LatencyHistogram,
    action_queue_delay: &mut ActionHistograms,
    action_request_to_ack: &mut ActionHistograms,
    interval_action_queue_delay: &mut ActionHistograms,
    interval_action_request_to_ack: &mut ActionHistograms,
) {
    queue_delay.record(value);
    request_to_ack.record(value);
    dimension_queue_delay.record(value);
    dimension_request_to_ack.record(value);
    interval_queue_delay.record(value);
    interval_request_to_ack.record(value);
    action_queue_delay.for_kind_mut(kind).record(value);
    action_request_to_ack.for_kind_mut(kind).record(value);
    interval_action_queue_delay.for_kind_mut(kind).record(value);
    interval_action_request_to_ack
        .for_kind_mut(kind)
        .record(value);
}
