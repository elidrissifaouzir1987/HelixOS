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

    // 3. B.apply(meme_hash) -> Err (rejeu refusé après restart), via le chemin ANTI-REJEU
    //    PERSISTÉ précisément — pas via « plan inconnu ».
    //
    // Fix F3 : après `load`, la map `plans` en mémoire de `kernel_b` est vide (elle n'a jamais vu
    // ce plan via `plan_intention`, seul `consumed_hashes` a été rechargé depuis
    // `consumed.jsonl`). `apply` échouerait donc de toute façon avec « plan inconnu » MÊME SI la
    // relecture du journal persisté ne fonctionnait pas du tout — un simple `is_err()` ne prouve
    // rien sur le mécanisme testé (persistance E2). On asserte donc le message EXACT renvoyé par
    // le garde `consumed_hashes.contains(plan_hash)` en tête d'`apply` (pipeline.rs ~:106-108),
    // qui s'exécute AVANT le lookup dans `plans` et est donc bien le chemin persisté, pas
    // « plan inconnu ».
    // `Outcome` (variante `Ok`) n'implémente pas `Debug`, donc `expect_err` n'est pas utilisable
    // directement ici : match explicite plutôt que d'ajouter `Debug` sur un type de production
    // pour un seul besoin de test.
    match kernel_b.apply(&hash) {
        Ok(_) => panic!("un noyau rechargé doit refuser de rejouer un plan déjà consommé"),
        Err(err) => assert_eq!(
            err, "plan déjà consommé (rejeu refusé, y compris après redémarrage)",
            "l'échec doit venir du chemin anti-rejeu PERSISTÉ (consumed_hashes rechargé par `load`), \
             pas d'un « plan inconnu » accidentel (plans en mémoire vide après restart)"
        ),
    }
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
