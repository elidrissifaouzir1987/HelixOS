#![cfg(feature = "test-fault-injection")]

#[test]
fn exact_non_test_t072_restore_pipeline_executes_end_to_end() {
    helix_coordinator_sqlite::run_t072_production_conformance_for_test_v1()
        .expect("production T072 conformance path succeeds");
}
