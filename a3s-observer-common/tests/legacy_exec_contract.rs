use a3s_observer_common::{LegacyExecEvent, ARGV_SLOTS, LEGACY_ARG_LEN};

#[test]
fn legacy_exec_event_keeps_linux_4_19_perf_abi() {
    assert_eq!(LEGACY_ARG_LEN, 128);
    assert_eq!(ARGV_SLOTS, 12);
    assert_eq!(
        core::mem::size_of::<LegacyExecEvent>(),
        4 * 4 + 16 + 128 + ARGV_SLOTS * LEGACY_ARG_LEN,
    );
}
