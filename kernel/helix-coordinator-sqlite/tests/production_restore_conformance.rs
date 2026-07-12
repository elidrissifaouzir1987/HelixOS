#![cfg(feature = "test-fault-injection")]

#[test]
fn exact_non_test_t072_restore_pipeline_matches_platform_contract() {
    // T086 uses this exact public-path result as the Windows refusal oracle before the
    // release process-kill executor applies its separate host-reachability partition.
    let expected = if cfg!(windows) {
        Err("restore-platform-unsupported")
    } else {
        Ok(())
    };

    assert_eq!(
        helix_coordinator_sqlite::run_t072_production_conformance_for_test_v1(),
        expected,
        "production T072 conformance path must preserve the reviewed platform contract"
    );
}
