#![forbid(unsafe_code)]
use helixos_kernel::intention::Intention;
use helixos_kernel::pipeline::Kernel;
use helixos_kernel::scope::ScopeLease;

#[test]
fn consumed_plan_stays_consumed_across_restart() {   // test 9 (persistance)
    let state_dir = std::env::temp_dir().join(format!("helix-restart-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();
    let target = state_dir.join("note.md");
    std::fs::write(&target, b"OLD").unwrap();
    let lease = ScopeLease { task_id: "t1".into(), roots: vec![state_dir.clone()] };

    // 1. Kernel A : plan + apply (consumed=true) -> l'état est persisté sur disque.
    let mut kernel_a = Kernel::new(state_dir.clone(), lease.clone()).unwrap();
    let plan = kernel_a
        .plan_intention("t1", "hermes", Intention::ProposeFilePatch { path: target.clone(), patch: "NEW".into() }, false)
        .unwrap();
    let hash = plan.plan_hash.clone();
    kernel_a.apply(&hash).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"NEW");

    // 2. Kernel B : recharge l'état depuis le même chemin.
    let mut kernel_b = Kernel::load(state_dir.clone(), lease).unwrap();

    // 3. B.apply(meme_hash) -> Err (rejeu refusé après restart).
    let result = kernel_b.apply(&hash);
    assert!(result.is_err(), "un noyau rechargé doit refuser de rejouer un plan déjà consommé");
}

#[test]
fn load_of_kernel_with_no_prior_state_starts_with_empty_consumed_set() {
    // Un `load` sur un `state_dir` neuf (jamais utilisé) ne doit pas planter et ne doit
    // rien considérer comme déjà consommé.
    let state_dir = std::env::temp_dir().join(format!("helix-restart-fresh-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();
    let target = state_dir.join("note.md");
    std::fs::write(&target, b"OLD").unwrap();
    let lease = ScopeLease { task_id: "t1".into(), roots: vec![state_dir.clone()] };

    let mut kernel = Kernel::load(state_dir.clone(), lease).unwrap();
    let plan = kernel
        .plan_intention("t1", "hermes", Intention::ProposeFilePatch { path: target.clone(), patch: "NEW".into() }, false)
        .unwrap();
    let hash = plan.plan_hash.clone();
    assert!(kernel.apply(&hash).is_ok(), "un état neuf ne doit refuser aucun plan légitime");
}
