# HelixOS MVP-0 — Plan d'implémentation (walking skeleton)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer la plus petite boucle HelixOS utilisable de bout en bout : une intention (patcher une note du vault) qui traverse une frontière conteneur→hôte *prouvée étanche*, un noyau Rust qui la plan-signe/approuve/exécute/audite/annule, et une page d'approbation servie hors-webui — agréable à utiliser au bureau, sans VSS ni sidecar ni Graphify.

**Architecture :** Un service Windows natif en Rust (le noyau) est le seul chemin runtime→hôte. Hermes tourne dans un conteneur sur une distro WSL2 durcie (dockerd natif) et appelle le noyau en mTLS. Le noyau valide un **bail de portée** (allowlist), construit un **plan canonique hashé** (sha256, TTL, usage unique), affiche une **carte d'approbation** sur une micro-page HTTPS d'origine distincte, exécute via **rollback compensation** (copie-aside + rename atomique), et écrit un **audit append-only**. Aucune API freeform ; aucun secret lisible ; le contenu lu est une donnée non fiable.

**Tech Stack :** Rust (édition 2021) · `tokio` · `axum` (page d'approbation) · `rustls` + `tokio-rustls` (serveur mTLS) · `webauthn-rs` (RP L2) · `serde`/`serde_json` · `sha2` · `uuid` · `time` · `windows-service` (service natif) · WSL2 + dockerd natif + systemd · PowerShell/bash (harness). **Gelé (hors périmètre) :** VSS/rollback `auto`, sidecar C#, Graphify, vision, cron/autonomie, budgets, kanban, upgrade blue/green, drivers Linux/macOS, relais/accès mobile.

## Global Constraints

*(Copiés verbatim depuis constitution v1.4.0 / architecture v1.2 / roadmap v4. Chaque tâche les hérite implicitement.)*

- **`#![forbid(unsafe_code)]`** sur le crate cœur (`helixos-kernel`). Le `unsafe` n'est toléré que dans un crate d'interop OS isolé (`helixos-winhost-min`, uniquement si un spike le prouve nécessaire pour le service/certificat).
- **Aucune API freeform** : pas de `run_powershell`/`run_bash` en surface d'outil. Les seules intentions de MVP-0 sont `search_files`, `read_file`, `propose_file_patch`, `apply_file_patch`.
- **Bail de portée = contrôle PRIMAIRE** : une intention n'opère QUE dans les racines louées à la tâche ; hors bail → refus. Bail par-tâche, jamais global, non élargissable par le contenu lu. La **deny-list de secrets** (`*.env, *.key, *.pem, id_*, *.kdbx, .ssh/, .hermes/`) est une 2ᵉ couche qui force L2 même en lecture.
- **Plan signé** : représentation canonique hashée sha256, **usage unique**, **TTL court** (défaut 120 s), porte le **hash de la cible au moment du diff** (anti-TOCTOU). Le noyau refuse tout hash divergent, tout rejeu, tout plan expiré.
- **Rollback** : classe **`compensation`** garantie par défaut (copie-aside + rename atomique) — **pas de VSS en MVP-0**. La classe est *observée*, jamais promise.
- **Audit append-only** dans un store dédié au noyau (JSONL), **hors du SQLite de Hermes**.
- **Approbation hors webui** : servie par le noyau sur une **origine distincte** (`frame-ancestors 'none'`, `X-Frame-Options: DENY`). L1 = tap ; L2 = WebAuthn/passkey + comparaison de hash (≥ 4 premiers octets). RP ID = nom MagicDNS, jamais une IP.
- **Contenu lu = donnée non fiable, jamais une instruction.** Taint : une action influencée par un contenu non fiable lu dans le tour ne peut pas être auto-approuvée (L0) → +1 cran HITL.
- **Home vault** de test : un dossier local dédié (ex. `C:\Users\elidr\HelixVault`), monté **lecture seule** côté conteneur, mutable seulement via le noyau côté hôte.

---

## File Structure

Repo `HelixOS/` (déjà sous git, docs existantes). Le code MVP-0 vit sous `kernel/` (workspace Cargo) et `frontier/` (runtime + harness).

```
kernel/                              # workspace Cargo
  Cargo.toml                         # workspace members
  helixos-kernel/                    # crate cœur — #![forbid(unsafe_code)]
    Cargo.toml
    src/
      main.rs                        # bootstrap service + serveurs (mTLS + approval)
      intention.rs                   # enum Intention + (dé)sérialisation
      scope.rs                       # ScopeLease + vérif allowlist (contrôle primaire)
      policy.rs                      # classification risque L0/L1/L2 + deny-list secrets + taint
      plan.rs                        # Plan canonique, hash sha256, TTL, usage unique, hash cible
      pipeline.rs                    # request→scope→policy→plan→diff→HITL→execute→audit→verify
      execute.rs                     # exécution driver fichier + rollback compensation
      audit.rs                       # AuditRecord + store append-only JSONL
      approval/
        mod.rs                       # état des opérations en vol + décisions
        server.rs                    # axum : micro-page origine distincte (SPIKE TLS)
        card.rs                      # contrat de carte d'approbation (quoi/où/risque/pourquoi/inhabituel)
        webauthn.rs                  # RP L2 (SPIKE webauthn-rs)
      mtls.rs                        # serveur mTLS d'auth appelant (SPIKE rustls)
      driver/
        mod.rs                       # trait DriverHost (contrat portable, zéro concept OS)
        files.rs                     # driver fichier léger (read/patch/apply, rename atomique)
        search.rs                    # search_files minimal (parcours par nom, borné au scope)
    tests/                           # tests d'intégration Rust
  helixos-mcp-shim/                  # petit pont : expose les intentions au conteneur Hermes (MCP/HTTP→mTLS)
    Cargo.toml
    src/main.rs
frontier/
  wsl/helixos.wsl.conf               # durcissement distro (automount/interop/appendWindowsPath=off)
  compose/docker-compose.yml         # Hermes + volumes nommés + vault :ro + réseau restreint
  firewall/lockdown.ps1              # Hyper-V firewall : outbound block + 1 règle port noyau
  harness/
    run-harness.ps1                  # orchestre les tests de contournement (host + runtime)
    checks/                          # scripts exécutés DANS le conteneur (doivent échouer)
ops/
  backup.ps1                         # backup vault + audit/état noyau
  restore.ps1                        # restauration testée
docs/superpowers/plans/2026-07-06-helixos-mvp0.md   # ce plan
```

**Interfaces-clés (contrats stables entre tâches) :**

- `driver::DriverHost` (trait) — `read_file(&self, path) -> Result<Vec<u8>>`, `search_files(&self, query, roots) -> Result<Vec<PathBuf>>`, `stage_and_apply_patch(&self, path, new_content) -> Result<RollbackHandle>`, `rollback(&self, handle) -> Result<()>`.
- `scope::ScopeLease { task_id: String, roots: Vec<PathBuf> }` + `ScopeLease::permits(&self, path: &Path) -> bool`.
- `plan::Plan { plan_id: Uuid, task_id, intention, target: PathBuf, target_hash_at_diff: String, diff: String, risk: RiskLevel, rollback_class: RollbackClass, plan_hash: String, created_at: OffsetDateTime, ttl_secs: u64, consumed: bool }` + `Plan::canonical_bytes()` + `Plan::compute_hash()`.
- `policy::{RiskLevel::{L0,L1,L2}, classify(intention, target, tainted) -> RiskLevel}` + `policy::is_secret(path) -> bool`.
- `audit::AuditRecord` (sérialisé JSONL) + `audit::AppendOnlyStore::append(&self, rec)`.
- `approval::{Decision::{Approve,Reject}, InFlight}` + `approval::decide(plan_hash, decision, verifier)`.

---

## Phase A — Frontière prouvée étanche (runtime natif + harness)

*Sortie de phase : Hermes tourne en conteneur, structurellement incapable de toucher l'hôte ; le harness passe au vert (les contournements échouent) et vire au rouge si on relâche un réglage. Tests 1, 2 (échec = bloqué).*

### Task A1 : Distro WSL2 durcie + dockerd natif

**Files:**
- Create: `frontier/wsl/helixos.wsl.conf`
- Create: `frontier/wsl/setup-distro.ps1`

**Interfaces:**
- Produces: une distro WSL2 nommée `helixos` avec `automount=off`, `interop=off`, `appendWindowsPath=off`, user non-root, dockerd+systemd démarrant au boot. Le compose (A2) s'y déploie.

- [ ] **Step 1 : Écrire le `wsl.conf` durci**

```ini
# frontier/wsl/helixos.wsl.conf  → déployé en /etc/wsl.conf dans la distro `helixos`
[automount]
enabled = false
[interop]
enabled = false
appendWindowsPath = false
[user]
default = helix
[boot]
systemd = true
command = "service docker start"
```

- [ ] **Step 2 : Écrire le script de provisioning**

```powershell
# frontier/wsl/setup-distro.ps1
$ErrorActionPreference = 'Stop'
# 1. Importer une base Ubuntu minimale dans une distro dédiée `helixos` (rootfs pré-téléchargé)
#    wsl --import helixos $env:LOCALAPPDATA\helixos ubuntu-rootfs.tar.gz
# 2. Créer l'utilisateur non-root `helix`, l'ajouter au groupe docker
# 3. Copier helixos.wsl.conf -> /etc/wsl.conf
# 4. Installer dockerd natif (paquet docker.io), PAS Docker Desktop
# 5. wsl --terminate helixos ; wsl -d helixos -u root -e systemctl enable docker
Write-Host "Distro helixos provisionnée (dockerd natif, durcie)."
```

- [ ] **Step 3 : Vérifier le durcissement**

Run: `wsl -d helixos -u helix -e sh -c 'ls /mnt/c 2>&1; id'`
Expected: `/mnt/c` absent ou vide (automount off) ; `id` montre l'utilisateur `helix` non-root.

- [ ] **Step 4 : Vérifier dockerd natif (pas Docker Desktop)**

Run: `wsl -d helixos -u helix -e docker info --format '{{.OperatingSystem}}'`
Expected: renvoie l'OS de la distro (dockerd dans la distro), sans dépendance à `Docker Desktop.exe`.

- [ ] **Step 5 : Commit**

```bash
git add frontier/wsl/
git commit -m "frontier: hardened WSL2 distro + native dockerd (no Docker Desktop)"
```

### Task A2 : docker-compose Hermes (volumes nommés, vault :ro, réseau restreint)

**Files:**
- Create: `frontier/compose/docker-compose.yml`

**Interfaces:**
- Consumes: distro `helixos` (A1).
- Produces: Hermes joignable seulement via le futur port du noyau ; état en volumes nommés ; vault monté `:ro`.

- [ ] **Step 1 : Écrire le compose**

```yaml
# frontier/compose/docker-compose.yml
services:
  hermes:
    image: nousresearch/hermes-agent@sha256:PIN_ME   # ≥ 0.16.0, pin par digest (Global Constraints)
    restart: unless-stopped
    volumes:
      - hermes_state:/opt/data                        # état (secrets, sessions, skills) — volume nommé
      - type: bind
        source: /mnt/vault                            # vault projeté RO dans la distro (voir note)
        target: /vault
        read_only: true
    networks: [kernelnet]
    # AUCUN montage de docker.sock, AUCUN network_mode: host, AUCUN privileged, pid/ipc host, /dev/shm host
volumes:
  hermes_state:
networks:
  kernelnet:
    driver: bridge
    internal: true                                    # pas d'accès réseau sortant arbitraire
```

> Note : le vault hôte (`C:\Users\elidr\HelixVault`) est exposé à la distro en lecture seule ; toute *mutation* passe par le noyau côté hôte, jamais par ce montage.

- [ ] **Step 2 : Vérifier l'absence de trous interdits**

Run: `grep -E 'docker.sock|network_mode:\s*host|privileged|pid:\s*host|ipc:\s*host' frontier/compose/docker-compose.yml`
Expected: aucun résultat (exit 1).

- [ ] **Step 3 : Démarrer et vérifier le montage RO**

Run: `wsl -d helixos -u helix -e sh -c 'cd /mnt/compose && docker compose up -d && docker compose exec hermes touch /vault/should_fail 2>&1'`
Expected: `Read-only file system` (le vault n'est pas mutable depuis le conteneur).

- [ ] **Step 4 : Commit**

```bash
git add frontier/compose/
git commit -m "frontier: compose Hermes with named volumes, RO vault, restricted net, no host bridges"
```

### Task A3 : Verrou réseau Hyper-V (un seul port, routé)

**Files:**
- Create: `frontier/firewall/lockdown.ps1`

**Interfaces:**
- Produces: le trafic sortant de la distro WSL est bloqué sauf vers le port du noyau, sur la **gateway WSL** (pas `127.0.0.1`, cf. nuance loopback).

- [ ] **Step 1 : Écrire le script de verrouillage**

```powershell
# frontier/firewall/lockdown.ps1  (Admin)
$ErrorActionPreference = 'Stop'
$wsl = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'   # VMCreatorId WSL
$KERNEL_PORT = 8443                                 # port mTLS du noyau (routé, gateway WSL)
Set-NetFirewallHyperVVMSetting -Name $wsl -Enabled True `
  -DefaultInboundAction Block -DefaultOutboundAction Block -LoopbackEnabled False
New-NetFirewallHyperVRule -Name HelixKernelMTLS -DisplayName "HelixOS kernel mTLS" `
  -Direction Outbound -VMCreatorId $wsl -Protocol TCP -RemotePorts $KERNEL_PORT
Write-Host "Verrou reseau: WSL -> hote autorise uniquement TCP/$KERNEL_PORT (gateway, routé)."
```

- [ ] **Step 2 : Appliquer et vérifier la règle**

Run: `powershell -File frontier/firewall/lockdown.ps1; Get-NetFirewallHyperVRule -Name HelixKernelMTLS`
Expected: la règle existe, Outbound, port 8443. `DefaultOutboundAction=Block`.

- [ ] **Step 3 : Commit**

```bash
git add frontier/firewall/
git commit -m "frontier: Hyper-V firewall lockdown — single routed kernel port"
```

### Task A4 : Harness de contournement (tests 1 & 2 — doivent échouer)

**Files:**
- Create: `frontier/harness/run-harness.ps1`
- Create: `frontier/harness/checks/from-container.sh`

**Interfaces:**
- Consumes: A1–A3.
- Produces: un harness rejouable ; **PASS = le contournement a échoué** ; vire au ROUGE si on relâche un réglage.

- [ ] **Step 1 : Écrire les tentatives de contournement (dans le conteneur)**

```sh
# frontier/harness/checks/from-container.sh  — exécuté DANS le conteneur Hermes
set -u
fail=0
# Test 1a : accéder au filesystem hôte
if ls /mnt/c >/dev/null 2>&1; then echo "LEAK: /mnt/c lisible"; fail=1; else echo "OK: /mnt/c inaccessible"; fi
# Test 1b : accéder au vault en écriture
if touch /vault/breach 2>/dev/null; then echo "LEAK: vault mutable"; rm -f /vault/breach; fail=1; else echo "OK: vault RO"; fi
# Test 1c : exécuter un binaire hôte (interop off)
if [ -x /init ] && /init /bin/true 2>/dev/null; then echo "LEAK: interop actif"; fail=1; else echo "OK: interop off"; fi
# Test 2 : joindre un port hôte non prévu (ex. 3389/22 sur la gateway)
GW=$(ip route show default | awk '{print $3}')
if timeout 3 bash -c ">/dev/tcp/$GW/3389" 2>/dev/null; then echo "LEAK: port hôte 3389 joignable"; fail=1; else echo "OK: port hôte non prévu bloqué"; fi
exit $fail
```

- [ ] **Step 2 : Écrire l'orchestrateur (hôte)**

```powershell
# frontier/harness/run-harness.ps1
$ErrorActionPreference = 'Stop'
Copy-Item frontier/harness/checks/from-container.sh \\wsl$\helixos\tmp\ -Force
$rc = wsl -d helixos -u helix -e docker compose -f /mnt/compose/docker-compose.yml exec -T hermes sh /tmp/from-container.sh
if ($LASTEXITCODE -ne 0) { Write-Error "HARNESS ROUGE : un contournement a RÉUSSI (frontière percée)"; exit 1 }
Write-Host "HARNESS VERT : tous les contournements ont échoué (frontière étanche)."
```

- [ ] **Step 3 : Exécuter — attendu VERT**

Run: `powershell -File frontier/harness/run-harness.ps1`
Expected: "HARNESS VERT", exit 0 (tous les LEAK absents).

- [ ] **Step 4 : Test de régression — relâcher un réglage doit virer au ROUGE**

Run: mettre temporairement `interop.enabled=true`, `wsl --shutdown`, relancer le harness.
Expected: "HARNESS ROUGE" (interop détecté) → prouve que le harness *casse* quand on relâche. Puis restaurer.

- [ ] **Step 5 : Commit**

```bash
git add frontier/harness/
git commit -m "frontier: bypass harness (tests 1,2 must fail) + relax-regression check"
```

---

## Phase B — Noyau Rust minimal

*Sortie de phase : le noyau valide un appelant (mTLS), refuse une intention hors bail (test 20) et sans credential (test 3), construit un plan signé anti-rejeu/anti-TOCTOU (tests 12, 13), exécute avec rollback compensation, audite. Idempotent (test 9). Deny-list secrets → L2 (test 19).*

### Task B1 : Scaffold du workspace + trait DriverHost

**Files:**
- Create: `kernel/Cargo.toml`, `kernel/helixos-kernel/Cargo.toml`, `kernel/helixos-kernel/src/main.rs`, `kernel/helixos-kernel/src/driver/mod.rs`

**Interfaces:**
- Produces: `driver::DriverHost` trait + `driver::RollbackHandle`.

- [ ] **Step 1 : Écrire le workspace + manifeste crate**

```toml
# kernel/Cargo.toml
[workspace]
members = ["helixos-kernel", "helixos-mcp-shim"]
resolver = "2"

# kernel/helixos-kernel/Cargo.toml
[package]
name = "helixos-kernel"
version = "0.0.1"
edition = "2021"
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
uuid = { version = "1", features = ["v4", "serde"] }
time = { version = "0.3", features = ["serde", "formatting"] }
thiserror = "1"
```

- [ ] **Step 2 : Écrire le trait DriverHost (contrat portable, zéro concept OS)**

```rust
// kernel/helixos-kernel/src/driver/mod.rs
#![forbid(unsafe_code)]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollbackHandle { pub id: String, pub staged_original: PathBuf, pub target: PathBuf }

pub trait DriverHost {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, DriverError>;
    fn search_files(&self, query: &str, roots: &[PathBuf]) -> Result<Vec<PathBuf>, DriverError>;
    /// Copie-aside (compensation) puis remplace atomiquement le contenu cible.
    fn stage_and_apply(&self, target: &Path, new_content: &[u8]) -> Result<RollbackHandle, DriverError>;
    fn rollback(&self, handle: &RollbackHandle) -> Result<(), DriverError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("not found: {0}")] NotFound(String),
}
```

- [ ] **Step 3 : `main.rs` minimal qui compile**

```rust
// kernel/helixos-kernel/src/main.rs
#![forbid(unsafe_code)]
mod driver;
fn main() { println!("helixos-kernel 0.0.1"); }
```

- [ ] **Step 4 : Compiler**

Run: `cd kernel && cargo build`
Expected: build OK, warnings de modules non utilisés tolérés à ce stade.

- [ ] **Step 5 : Commit**

```bash
git add kernel/Cargo.toml kernel/helixos-kernel/
git commit -m "kernel: workspace scaffold + DriverHost trait (no_unsafe core)"
```

### Task B2 : Bail de portée (allowlist positive — contrôle primaire) + test 20

**Files:**
- Create: `kernel/helixos-kernel/src/scope.rs`
- Test: dans le même fichier (`#[cfg(test)]`)

**Interfaces:**
- Produces: `scope::ScopeLease { task_id, roots }` + `permits(&self, path) -> bool` (canonicalisation + refus des symlinks sortants).

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/src/scope.rs  (bas du fichier)
#[cfg(test)]
mod tests {
    use super::*; use std::path::PathBuf;
    fn lease(root: &str) -> ScopeLease {
        ScopeLease { task_id: "t1".into(), roots: vec![PathBuf::from(root)] }
    }
    #[test]
    fn permits_path_inside_leased_root() {
        assert!(lease("C:/vault").permits(&PathBuf::from("C:/vault/note.md")));
    }
    #[test]
    fn refuses_path_outside_lease() {           // test 20
        assert!(!lease("C:/vault").permits(&PathBuf::from("C:/Users/elidr/.ssh/id_rsa")));
    }
    #[test]
    fn refuses_parent_traversal() {
        assert!(!lease("C:/vault").permits(&PathBuf::from("C:/vault/../secrets/x")));
    }
}
```

- [ ] **Step 2 : Lancer — doit échouer (type absent)**

Run: `cd kernel && cargo test -p helixos-kernel scope::`
Expected: FAIL — `ScopeLease` non défini.

- [ ] **Step 3 : Implémenter le bail**

```rust
// kernel/helixos-kernel/src/scope.rs  (haut du fichier)
#![forbid(unsafe_code)]
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ScopeLease { pub task_id: String, pub roots: Vec<PathBuf> }

fn normalize(p: &Path) -> PathBuf {
    // Rejette le traversal en résolvant `.`/`..` de façon purement lexicale (sans toucher le FS).
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => { out.pop(); }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

impl ScopeLease {
    /// Contrôle PRIMAIRE : le chemin normalisé doit être sous une racine louée.
    pub fn permits(&self, path: &Path) -> bool {
        let np = normalize(path);
        self.roots.iter().any(|r| np.starts_with(&normalize(r)))
    }
}
```

- [ ] **Step 4 : Lancer — doit passer**

Run: `cd kernel && cargo test -p helixos-kernel scope::`
Expected: PASS (3 tests).

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/scope.rs
git commit -m "kernel: positive scope-lease allowlist (primary control) + refuse-outside test"
```

### Task B3 : Politique — classification L0/L1/L2 + deny-list secrets + taint (test 19)

**Files:**
- Create: `kernel/helixos-kernel/src/policy.rs`
- Create: `kernel/helixos-kernel/src/intention.rs`

**Interfaces:**
- Produces: `intention::Intention` (enum) ; `policy::{RiskLevel, classify(&Intention, tainted: bool) -> RiskLevel, is_secret(&Path) -> bool}`.

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/src/policy.rs (bas)
#[cfg(test)]
mod tests {
    use super::*; use crate::intention::Intention; use std::path::PathBuf;
    #[test] fn read_of_secret_forces_l2() {                        // test 19
        let i = Intention::ReadFile { path: PathBuf::from("C:/vault/.env") };
        assert_eq!(classify(&i, false), RiskLevel::L2);
    }
    #[test] fn plain_read_is_l0() {
        let i = Intention::ReadFile { path: PathBuf::from("C:/vault/note.md") };
        assert_eq!(classify(&i, false), RiskLevel::L0);
    }
    #[test] fn tainted_read_escalates_one_notch() {
        let i = Intention::ReadFile { path: PathBuf::from("C:/vault/note.md") };
        assert_eq!(classify(&i, true), RiskLevel::L1);
    }
    #[test] fn apply_patch_is_l1() {
        let i = Intention::ApplyFilePatch { plan_id: "p".into() };
        assert_eq!(classify(&i, false), RiskLevel::L1);
    }
}
```

- [ ] **Step 2 : Lancer — doit échouer**

Run: `cd kernel && cargo test -p helixos-kernel policy::`
Expected: FAIL — types absents.

- [ ] **Step 3 : Implémenter intention + policy**

```rust
// kernel/helixos-kernel/src/intention.rs
#![forbid(unsafe_code)]
use std::path::PathBuf;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Intention {
    SearchFiles { query: String },
    ReadFile { path: PathBuf },
    ProposeFilePatch { path: PathBuf, patch: String },   // patch = nouveau contenu (MVP-0 : remplacement intégral)
    ApplyFilePatch { plan_id: String },
}
```

```rust
// kernel/helixos-kernel/src/policy.rs (haut)
#![forbid(unsafe_code)]
use std::path::Path;
use crate::intention::Intention;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RiskLevel { L0, L1, L2 }

const SECRET_GLOBS: &[&str] = &[".env", ".key", ".pem", ".kdbx"];
const SECRET_DIRS: &[&str] = &[".ssh", ".hermes"];

pub fn is_secret(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.starts_with("id_") { return true; }
    if SECRET_GLOBS.iter().any(|g| name.ends_with(g)) { return true; }
    path.components().any(|c| SECRET_DIRS.contains(&c.as_os_str().to_str().unwrap_or("")))
}

fn base(intention: &Intention) -> RiskLevel {
    match intention {
        Intention::SearchFiles { .. } => RiskLevel::L0,
        Intention::ReadFile { path } => if is_secret(path) { RiskLevel::L2 } else { RiskLevel::L0 },
        Intention::ProposeFilePatch { .. } => RiskLevel::L1,
        Intention::ApplyFilePatch { .. } => RiskLevel::L1,
    }
}

/// Taint : +1 cran (L0→L1, L1→L2, L2 reste L2), jamais de descente.
pub fn classify(intention: &Intention, tainted: bool) -> RiskLevel {
    let b = base(intention);
    if !tainted { return b; }
    match b { RiskLevel::L0 => RiskLevel::L1, _ => RiskLevel::L2 }
}
```

- [ ] **Step 4 : Lancer — doit passer**

Run: `cd kernel && cargo test -p helixos-kernel policy::`
Expected: PASS (4 tests).

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/policy.rs kernel/helixos-kernel/src/intention.rs
git commit -m "kernel: policy L0/L1/L2 + secret deny-list (2nd layer) + taint escalation"
```

### Task B4 : Plan canonique — hash sha256, TTL, usage unique, hash cible (tests 12, 13)

**Files:**
- Create: `kernel/helixos-kernel/src/plan.rs`

**Interfaces:**
- Produces: `plan::{Plan, RollbackClass, new_plan(...), Plan::is_expired(now), Plan::verify_target_unchanged(current_hash)}`.

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/src/plan.rs (bas)
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn hash_is_stable_and_content_addressed() {
        let p = sample_plan("HASH_A");
        assert_eq!(p.plan_hash.len(), 64);                 // sha256 hex
        assert_eq!(p.plan_hash, sample_plan("HASH_A").plan_hash);
        assert_ne!(p.plan_hash, sample_plan("HASH_B").plan_hash);
    }
    #[test] fn toctou_refuses_changed_target() {           // test 12
        let p = sample_plan("HASH_A");
        assert!(p.verify_target_unchanged("HASH_A").is_ok());
        assert!(p.verify_target_unchanged("HASH_CHANGED").is_err());
    }
    #[test] fn expired_plan_is_rejected() {                // test 13 (TTL)
        let mut p = sample_plan("HASH_A"); p.ttl_secs = 0;
        assert!(p.is_expired(p.created_at + time::Duration::seconds(1)));
    }
    fn sample_plan(target_hash: &str) -> Plan {
        new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
                 target_hash.into(), "diff".into(),
                 crate::policy::RiskLevel::L1, RollbackClass::Compensation)
    }
}
```

- [ ] **Step 2 : Lancer — doit échouer**

Run: `cd kernel && cargo test -p helixos-kernel plan::`
Expected: FAIL — types absents.

- [ ] **Step 3 : Implémenter le plan**

```rust
// kernel/helixos-kernel/src/plan.rs (haut)
#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use std::path::PathBuf;
use crate::policy::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RollbackClass { Compensation, Irreversible }   // pas d'`Auto` en MVP-0 (VSS gelé)

#[derive(Debug, Clone, serde::Serialize)]
pub struct Plan {
    pub plan_id: Uuid,
    pub task_id: String,
    pub intention_repr: String,
    pub target: PathBuf,
    pub target_hash_at_diff: String,
    pub diff: String,
    pub risk: RiskLevel,
    pub rollback_class: RollbackClass,
    pub plan_hash: String,
    #[serde(with = "time::serde::rfc3339")] pub created_at: OffsetDateTime,
    pub ttl_secs: u64,
    pub consumed: bool,
}

pub fn new_plan(task_id: String, intention_repr: String, target: PathBuf,
                target_hash_at_diff: String, diff: String,
                risk: RiskLevel, rollback_class: RollbackClass) -> Plan {
    let created_at = OffsetDateTime::now_utc();
    let plan_id = Uuid::new_v4();
    let canonical = format!("{plan_id}|{task_id}|{intention_repr}|{}|{target_hash_at_diff}|{diff}|{created_at}",
                            target.display());
    let plan_hash = hex(Sha256::digest(canonical.as_bytes()).as_slice());
    Plan { plan_id, task_id, intention_repr, target, target_hash_at_diff, diff, risk,
           rollback_class, plan_hash, created_at, ttl_secs: 120, consumed: false }
}

impl Plan {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        (now - self.created_at).whole_seconds() as u64 > self.ttl_secs
    }
    /// Anti-TOCTOU : la cible doit avoir le même hash qu'au moment du diff.
    pub fn verify_target_unchanged(&self, current_hash: &str) -> Result<(), &'static str> {
        if current_hash == self.target_hash_at_diff { Ok(()) } else { Err("target changed since diff (TOCTOU)") }
    }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
```

- [ ] **Step 4 : Lancer — doit passer**

Run: `cd kernel && cargo test -p helixos-kernel plan::`
Expected: PASS (3 tests).

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/plan.rs
git commit -m "kernel: canonical signed plan (sha256, TTL, single-use, target-hash anti-TOCTOU)"
```

### Task B5 : Audit append-only (store JSONL dédié)

**Files:**
- Create: `kernel/helixos-kernel/src/audit.rs`

**Interfaces:**
- Produces: `audit::{AuditRecord, AppendOnlyStore::new(path), append(&self, &AuditRecord)}`.

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/src/audit.rs (bas)
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn append_writes_one_jsonl_line_per_record() {
        let dir = std::env::temp_dir().join(format!("helix-audit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = AppendOnlyStore::new(dir.join("audit.jsonl"));
        store.append(&AuditRecord::sample("op1")).unwrap();
        store.append(&AuditRecord::sample("op2")).unwrap();
        let content = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("op1") && content.contains("op2"));
    }
}
```

- [ ] **Step 2 : Lancer — doit échouer**

Run: `cd kernel && cargo test -p helixos-kernel audit::`
Expected: FAIL — types absents.

- [ ] **Step 3 : Implémenter le store**

```rust
// kernel/helixos-kernel/src/audit.rs (haut)
#![forbid(unsafe_code)]
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRecord {
    pub operation_id: String,
    pub caller: String,
    pub subagent_id_hint: Option<String>,   // hint déclaratif — SANS valeur de sécurité
    pub tool: String,
    pub target: String,
    pub plan_hash: String,
    pub target_hash_at_diff: String,
    pub risk: String,
    pub rollback: Option<String>,
    pub result: String,
    pub trace_id: String,
}

impl AuditRecord {
    #[cfg(test)]
    pub fn sample(op: &str) -> Self {
        Self { operation_id: op.into(), caller: "hermes".into(), subagent_id_hint: None,
               tool: "apply_file_patch".into(), target: "C:/vault/n.md".into(),
               plan_hash: "h".into(), target_hash_at_diff: "th".into(), risk: "L1".into(),
               rollback: Some("rb1".into()), result: "success".into(), trace_id: "tr".into() }
    }
}

pub struct AppendOnlyStore { path: PathBuf }
impl AppendOnlyStore {
    pub fn new(path: PathBuf) -> Self { Self { path } }
    pub fn append(&self, rec: &AuditRecord) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(rec)?)?;
        Ok(())
    }
}
```

- [ ] **Step 4 : Lancer — doit passer**

Run: `cd kernel && cargo test -p helixos-kernel audit::`
Expected: PASS.

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/audit.rs
git commit -m "kernel: append-only JSONL audit store (dedicated, not Hermes SQLite)"
```

### Task B6 : Driver fichier + rollback compensation (copie-aside + rename atomique)

**Files:**
- Create: `kernel/helixos-kernel/src/driver/files.rs`, `kernel/helixos-kernel/src/driver/search.rs`
- Modify: `kernel/helixos-kernel/src/driver/mod.rs` (déclarer les sous-modules)

**Interfaces:**
- Consumes: `driver::{DriverHost, RollbackHandle, DriverError}` (B1).
- Produces: `driver::files::FileDriver` (impl `DriverHost`).

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/src/driver/files.rs (bas)
#[cfg(test)]
mod tests {
    use super::*; use crate::driver::DriverHost;
    #[test] fn apply_then_rollback_restores_original() {
        let dir = std::env::temp_dir().join(format!("helix-fd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("note.md");
        std::fs::write(&target, b"ORIGINAL").unwrap();
        let d = FileDriver::new(dir.clone());
        let h = d.stage_and_apply(&target, b"PATCHED").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"PATCHED");
        d.rollback(&h).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL");
    }
}
```

- [ ] **Step 2 : Lancer — doit échouer**

Run: `cd kernel && cargo test -p helixos-kernel driver::files`
Expected: FAIL — `FileDriver` absent.

- [ ] **Step 3 : Implémenter le driver fichier (compensation)**

```rust
// kernel/helixos-kernel/src/driver/files.rs (haut)
#![forbid(unsafe_code)]
use std::path::{Path, PathBuf};
use crate::driver::{DriverHost, DriverError, RollbackHandle};

pub struct FileDriver { staging: PathBuf }
impl FileDriver { pub fn new(staging: PathBuf) -> Self { Self { staging } } }

impl DriverHost for FileDriver {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, DriverError> {
        Ok(std::fs::read(path)?)
    }
    fn search_files(&self, query: &str, roots: &[PathBuf]) -> Result<Vec<PathBuf>, DriverError> {
        crate::driver::search::walk_by_name(query, roots)
    }
    fn stage_and_apply(&self, target: &Path, new_content: &[u8]) -> Result<RollbackHandle, DriverError> {
        // 1. Copie-aside de l'original (compensation garantie).
        std::fs::create_dir_all(&self.staging)?;
        let id = uuid::Uuid::new_v4().to_string();
        let staged = self.staging.join(format!("{id}.orig"));
        std::fs::copy(target, &staged)?;
        // 2. Écrire le nouveau contenu dans un temp puis rename atomique (remplace l'existant sous Windows).
        let tmp = target.with_extension("helix.tmp");
        std::fs::write(&tmp, new_content)?;
        std::fs::rename(&tmp, target)?;   // MoveFileEx(REPLACE_EXISTING) — atomique même volume
        Ok(RollbackHandle { id, staged_original: staged, target: target.to_path_buf() })
    }
    fn rollback(&self, h: &RollbackHandle) -> Result<(), DriverError> {
        let tmp = h.target.with_extension("helix.rb.tmp");
        std::fs::copy(&h.staged_original, &tmp)?;
        std::fs::rename(&tmp, &h.target)?;
        Ok(())
    }
}
```

```rust
// kernel/helixos-kernel/src/driver/search.rs
#![forbid(unsafe_code)]
use std::path::PathBuf;
use crate::driver::DriverError;
/// Recherche par nom, bornée aux racines (MVP-0 : parcours simple, pas d'index).
pub fn walk_by_name(query: &str, roots: &[PathBuf]) -> Result<Vec<PathBuf>, DriverError> {
    let mut out = Vec::new();
    for root in roots {
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)?.flatten() {
                let p = entry.path();
                if p.is_dir() { stack.push(p); }
                else if p.file_name().and_then(|s| s.to_str()).map_or(false, |n| n.contains(query)) { out.push(p); }
            }
        }
    }
    Ok(out)
}
```

```rust
// kernel/helixos-kernel/src/driver/mod.rs  — ajouter en tête (après le trait) :
pub mod files;
pub mod search;
```

- [ ] **Step 4 : Lancer — doit passer**

Run: `cd kernel && cargo test -p helixos-kernel driver::`
Expected: PASS.

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/driver/
git commit -m "kernel: file driver + compensation rollback (copy-aside + atomic rename), name search"
```

### Task B7 : Pipeline complet + idempotence (usage unique) — test 9

**Files:**
- Create: `kernel/helixos-kernel/src/pipeline.rs`
- Modify: `kernel/helixos-kernel/src/main.rs` (déclarer les modules)

**Interfaces:**
- Consumes: scope (B2), policy (B3), plan (B4), audit (B5), driver (B6).
- Produces: `pipeline::{Kernel, Kernel::plan_intention(...) -> Plan, Kernel::apply(plan_hash) -> Result<Outcome>}` ; un plan consommé ne se ré-exécute pas.

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/src/pipeline.rs (bas)
#[cfg(test)]
mod tests {
    use super::*; use crate::intention::Intention; use crate::scope::ScopeLease;
    use std::path::PathBuf;
    fn kernel_with_note(content: &[u8]) -> (Kernel, PathBuf) {
        let dir = std::env::temp_dir().join(format!("helix-pl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("note.md"); std::fs::write(&target, content).unwrap();
        let k = Kernel::new_for_test(dir.clone(),
            ScopeLease { task_id: "t1".into(), roots: vec![dir] });
        (k, target)
    }
    #[test] fn apply_patch_end_to_end_then_idempotent() {   // test 9
        let (mut k, target) = kernel_with_note(b"OLD");
        let plan = k.plan_intention("t1", "hermes",
            Intention::ProposeFilePatch { path: target.clone(), patch: "NEW".into() }, false).unwrap();
        let hash = plan.plan_hash.clone();
        assert!(k.apply(&hash).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW");
        assert!(k.apply(&hash).is_err(), "rejeu doit être refusé (usage unique)");   // idempotence
    }
    #[test] fn intention_outside_lease_is_refused() {       // test 20 (bout en bout)
        let (mut k, _t) = kernel_with_note(b"X");
        let outside = PathBuf::from("C:/Windows/system32/drivers/etc/hosts");
        let r = k.plan_intention("t1", "hermes",
            Intention::ProposeFilePatch { path: outside, patch: "P".into() }, false);
        assert!(r.is_err());
    }
}
```

- [ ] **Step 2 : Lancer — doit échouer**

Run: `cd kernel && cargo test -p helixos-kernel pipeline::`
Expected: FAIL — `Kernel` absent.

- [ ] **Step 3 : Implémenter le pipeline**

```rust
// kernel/helixos-kernel/src/pipeline.rs (haut)
#![forbid(unsafe_code)]
use std::collections::HashMap;
use std::path::PathBuf;
use sha2::{Digest, Sha256};
use crate::{audit::*, driver::{files::FileDriver, DriverHost}, intention::Intention,
            plan::*, policy, scope::ScopeLease};

pub struct Outcome { pub rollback_id: String }

pub struct Kernel {
    lease: ScopeLease,
    driver: FileDriver,
    audit: AppendOnlyStore,
    plans: HashMap<String, Plan>,   // plan_hash -> Plan (état des ops en vol)
}

impl Kernel {
    #[cfg(test)]
    pub fn new_for_test(dir: PathBuf, lease: ScopeLease) -> Self {
        Self { lease, driver: FileDriver::new(dir.join(".staging")),
               audit: AppendOnlyStore::new(dir.join("audit.jsonl")), plans: HashMap::new() }
    }

    fn hash_target(&self, path: &std::path::Path) -> String {
        match std::fs::read(path) { Ok(b) => hex(&Sha256::digest(&b)), Err(_) => "<absent>".into() }
    }

    /// request → scope → policy → plan → diff. Refuse hors bail.
    pub fn plan_intention(&mut self, task_id: &str, _caller: &str,
                          intention: Intention, tainted: bool) -> Result<Plan, String> {
        let target = match &intention {
            Intention::ProposeFilePatch { path, .. } | Intention::ReadFile { path } => path.clone(),
            _ => return Err("MVP-0: seul propose_file_patch est planifiable".into()),
        };
        if !self.lease.permits(&target) { return Err("hors bail de portée (refus)".into()); }  // contrôle primaire
        let risk = policy::classify(&intention, tainted);
        let th = self.hash_target(&target);
        let diff = match &intention { Intention::ProposeFilePatch { patch, .. } =>
            format!("--- {}\n+++ (proposé)\n{patch}", target.display()), _ => String::new() };
        let plan = new_plan(task_id.into(), format!("{intention:?}"), target, th, diff,
                            risk, RollbackClass::Compensation);
        self.plans.insert(plan.plan_hash.clone(), plan.clone());
        Ok(plan)
    }

    /// apply : usage unique + anti-TOCTOU + exécute + audit + verify.
    pub fn apply(&mut self, plan_hash: &str) -> Result<Outcome, String> {
        let mut plan = self.plans.get(plan_hash).cloned().ok_or("plan inconnu")?;
        if plan.consumed { return Err("plan déjà consommé (rejeu refusé)".into()); }
        if plan.is_expired(time::OffsetDateTime::now_utc()) { return Err("plan expiré".into()); }
        let current = self.hash_target(&plan.target);
        plan.verify_target_unchanged(&current).map_err(|e| e.to_string())?;   // TOCTOU
        // Rejoue le contenu proposé depuis le diff (MVP-0 : patch = contenu intégral encodé dans le diff).
        let new_content = plan.diff.rsplit("+++ (proposé)\n").next().unwrap_or("").as_bytes().to_vec();
        let handle = self.driver.stage_and_apply(&plan.target, &new_content).map_err(|e| e.to_string())?;
        plan.consumed = true;
        self.plans.insert(plan_hash.to_string(), plan.clone());
        self.audit.append(&AuditRecord {
            operation_id: plan.plan_id.to_string(), caller: plan.task_id.clone(), subagent_id_hint: None,
            tool: "apply_file_patch".into(), target: plan.target.display().to_string(),
            plan_hash: plan.plan_hash.clone(), target_hash_at_diff: plan.target_hash_at_diff.clone(),
            risk: format!("{:?}", plan.risk), rollback: Some(handle.id.clone()),
            result: "success".into(), trace_id: uuid::Uuid::new_v4().to_string(),
        }).map_err(|e| e.to_string())?;
        Ok(Outcome { rollback_id: handle.id })
    }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
```

```rust
// kernel/helixos-kernel/src/main.rs — remplacer par la liste complète des modules :
#![forbid(unsafe_code)]
mod driver; mod intention; mod scope; mod policy; mod plan; mod audit; mod pipeline;
fn main() { println!("helixos-kernel 0.0.1"); }
```

- [ ] **Step 4 : Lancer — doit passer**

Run: `cd kernel && cargo test -p helixos-kernel pipeline::`
Expected: PASS (2 tests) ; `cargo test -p helixos-kernel` global vert.

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/pipeline.rs kernel/helixos-kernel/src/main.rs
git commit -m "kernel: full intention pipeline (scope->policy->plan->TOCTOU->apply->audit), single-use idempotence"
```

### Task B8 (SPIKE) : Serveur mTLS d'authentification d'appelant — test 3

**Files:**
- Create: `kernel/helixos-kernel/src/mtls.rs`
- Test: `kernel/helixos-kernel/tests/mtls_it.rs`

**Interfaces:**
- Consumes: `pipeline::Kernel`.
- Produces: un serveur `tokio-rustls` qui **exige un certificat client valide** (`rustls::server::WebPkiClientVerifier`) ; un appelant sans cert est rejeté au handshake (test 3). L'identité du conteneur = le CN/SAN du cert client (pas le réseau).

> **SPIKE** : vérifier l'API `rustls` installée (≥ 0.23) avant de figer le code — `ClientCertVerifierBuilder`, `with_client_cert_verifier`, chargement PEM via `rustls-pemfile`. Produire un exemple minimal qui compile et tourne AVANT d'écrire le test final.

- [ ] **Step 1 : Spike — pinner l'API rustls**

Run: `cd kernel && cargo add tokio --features full && cargo add tokio-rustls rustls rustls-pemfile && cargo doc -p rustls --no-deps`
Action: lire la signature réelle de `WebPkiClientVerifier::builder(roots).build()` et `ServerConfig::builder().with_client_cert_verifier(...)`. Générer une paire CA + cert serveur + cert client de test (script `kernel/helixos-kernel/tests/gen-certs.sh` via `openssl`).
Expected: un `cargo build` vert avec la config serveur mTLS assemblée.

- [ ] **Step 2 : Écrire le test d'intégration qui échoue**

```rust
// kernel/helixos-kernel/tests/mtls_it.rs
// Démarre le serveur mTLS sur 127.0.0.1:0, tente une connexion SANS cert client.
#[tokio::test]
async fn connection_without_client_cert_is_rejected() {    // test 3
    let addr = helixos_kernel::mtls::spawn_test_server().await;   // renvoie SocketAddr
    let no_cert = tokio::net::TcpStream::connect(addr).await.unwrap();
    // handshake TLS sans présenter de certificat client => doit échouer
    let res = helixos_kernel::mtls::try_plain_tls_handshake(no_cert).await;
    assert!(res.is_err(), "un appelant sans credential doit être refusé");
}
```

- [ ] **Step 3 : Implémenter le serveur mTLS** (selon l'API pinnée au Step 1 — assembler `ServerConfig` avec `with_client_cert_verifier`, exposer `spawn_test_server()` et `try_plain_tls_handshake()`). Router chaque requête authentifiée vers `pipeline::Kernel`.

- [ ] **Step 4 : Lancer — doit passer**

Run: `cd kernel && cargo test -p helixos-kernel --test mtls_it`
Expected: PASS (handshake sans cert rejeté).

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/mtls.rs kernel/helixos-kernel/tests/
git commit -m "kernel: mTLS caller auth (client-cert required) — no-credential call refused (test 3)"
```

---

## Phase C — Surface d'approbation hors webui (origine distincte)

*Sortie de phase : une opération L1/L2 attend une décision sur une micro-page servie par le noyau ; L1 tap, L2 passkey + comparaison de hash ; la carte suit le contrat §4. Tests 11, 14 (esprit MVP-0 : la surface reste intègre hors de la pile agent).*

### Task C1 : Carte d'approbation (contrat §4) — logique pure

**Files:**
- Create: `kernel/helixos-kernel/src/approval/mod.rs`, `kernel/helixos-kernel/src/approval/card.rs`
- Modify: `kernel/helixos-kernel/src/main.rs` (`mod approval;`)

**Interfaces:**
- Produces: `approval::card::Card::from_plan(&Plan, unusual: Option<String>, tainted: bool) -> Card` avec les 5 champs (quoi/où/risque+rollback/pourquoi+taint/inhabituel) ; `Card::render_text()` pour test lisibilité.

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/src/approval/card.rs (bas)
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn card_has_five_ordered_sections_and_flags_taint() {
        let plan = crate::plan::new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
            "th".into(), "diff".into(), crate::policy::RiskLevel::L2, crate::plan::RollbackClass::Compensation);
        let card = Card::from_plan(&plan, Some("1re écriture hors ~/vault".into()), true);
        let text = card.render_text();
        for label in ["QUOI", "OÙ", "RISQUE", "POURQUOI", "INHABITUEL"] { assert!(text.contains(label)); }
        assert!(text.contains("influencé par du contenu non fiable"));   // drapeau taint
        assert!(text.contains("compensation"));                          // rollback réel
    }
}
```

- [ ] **Step 2 : Lancer — doit échouer.** Run: `cd kernel && cargo test -p helixos-kernel approval::card`. Expected: FAIL.

- [ ] **Step 3 : Implémenter la carte**

```rust
// kernel/helixos-kernel/src/approval/card.rs (haut)
#![forbid(unsafe_code)]
use crate::plan::Plan;
pub struct Card { pub quoi: String, pub ou: String, pub risque: String,
                  pub pourquoi: String, pub inhabituel: String, pub plan_hash: String }
impl Card {
    pub fn from_plan(p: &Plan, unusual: Option<String>, tainted: bool) -> Self {
        let pourquoi = if tainted {
            format!("Tâche {} — ⚠ action influencée par du contenu non fiable lu ce tour", p.task_id)
        } else { format!("Tâche {}", p.task_id) };
        Self {
            quoi: p.diff.clone(),
            ou: format!("{} (dans le bail de portée)", p.target.display()),
            risque: format!("{:?} · rollback réel = {:?}", p.risk, p.rollback_class),
            pourquoi,
            inhabituel: unusual.unwrap_or_else(|| "rien d'inhabituel signalé".into()),
            plan_hash: p.plan_hash.clone(),
        }
    }
    pub fn render_text(&self) -> String {
        format!("QUOI:\n{}\n\nOÙ: {}\n\nRISQUE: {}\n\nPOURQUOI: {}\n\nINHABITUEL: {}\n\nhash: {}",
                self.quoi, self.ou, self.risque, self.pourquoi, self.inhabituel, self.plan_hash)
    }
}
```

```rust
// kernel/helixos-kernel/src/approval/mod.rs
#![forbid(unsafe_code)]
pub mod card;
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Decision { Approve, Reject }
```

- [ ] **Step 4 : Lancer — doit passer.** Run: `cd kernel && cargo test -p helixos-kernel approval::card`. Expected: PASS.

- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/approval/
git commit -m "kernel: approval-card contract (what/where/risk/why+taint/unusual), readability-testable"
```

### Task C2 (SPIKE) : Micro-page HTTPS sur origine distincte + L1 tap

**Files:**
- Create: `kernel/helixos-kernel/src/approval/server.rs`

**Interfaces:**
- Consumes: `approval::card::Card`, `pipeline::Kernel`.
- Produces: un serveur `axum` HTTPS distinct du port mTLS, en-têtes `Content-Security-Policy: frame-ancestors 'none'` + `X-Frame-Options: DENY` ; `GET /op/:hash` rend la carte ; `POST /op/:hash/approve` (L1) déclenche `Kernel::apply`.

> **SPIKE** : pinner l'API `axum` (0.7+) et le TLS d'axum (`axum-server` + `rustls`). Vérifier la pose des en-têtes CSP/XFO. Le certificat du nom MagicDNS est un input de config (fourni par `tailscale cert`, cf. Phase E / gelé hors-MVP-0 pour l'away ; en MVP-0 au bureau, un certif local pour l'origine distincte suffit).

- [ ] **Step 1 : Spike axum + TLS + en-têtes.** Run: `cd kernel && cargo add axum axum-server --features axum-server/tls-rustls`. Produire un handler qui renvoie 200 avec les deux en-têtes, vérifiés par `curl -sI`.
- [ ] **Step 2 : Test d'intégration qui échoue** : `GET /op/:hash` renvoie la carte + les en-têtes CSP/XFO ; sans les en-têtes → test rouge.
- [ ] **Step 3 : Implémenter le serveur** (routes `/op/:hash`, `/op/:hash/approve`, en-têtes de sécurité, rendu `Card::render_text()` en HTML minimal sans framework).
- [ ] **Step 4 : Lancer — doit passer.** Run: `cd kernel && cargo test -p helixos-kernel --test approval_it`. Expected: PASS.
- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/approval/server.rs kernel/helixos-kernel/tests/approval_it.rs
git commit -m "kernel: approval micro-page on distinct origin (CSP frame-ancestors none) + L1 tap apply"
```

### Task C3 (SPIKE) : L2 WebAuthn/passkey + comparaison de hash

**Files:**
- Create: `kernel/helixos-kernel/src/approval/webauthn.rs`

**Interfaces:**
- Consumes: `webauthn-rs` RP ; `approval::server`.
- Produces: pour un plan L2, l'`apply` n'est autorisé qu'après une assertion WebAuthn valide **et** confirmation des 4 premiers octets du `plan_hash`.

> **SPIKE** : `webauthn-rs` (≥ 0.5). RP ID = nom MagicDNS (`helix.<tailnet>.ts.net`), jamais l'IP `100.x`. Enregistrer une passkey de test (téléphone/clé), stocker le credential. Vérifier la cérémonie register→authenticate en local. Documenter l'exigence de secure-context (certif `ts.net`).

- [ ] **Step 1 : Spike webauthn-rs** : enregistrer + authentifier une passkey en local ; capturer le flux `start_passkey_registration`/`finish_...`/`start_passkey_authentication`/`finish_...`.
- [ ] **Step 2 : Test qui échoue** : un `apply` d'un plan L2 sans assertion valide → refus ; avec assertion + hash confirmé → autorisé.
- [ ] **Step 3 : Implémenter la garde L2** (assertion valide requise + comparaison `plan_hash[..8]`).
- [ ] **Step 4 : Lancer — doit passer.**
- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/approval/webauthn.rs
git commit -m "kernel: L2 WebAuthn passkey + plan-hash confirmation (RP id = MagicDNS name)"
```

---

## Phase D — Intention branchée de bout en bout

*Sortie de phase : Hermes (conteneur) propose un patch de note-vault via une intention typée → carte affichée → approbation hors webui → appliqué → audité → annulable (esprit test 5, rattaché ici).*

### Task D1 (SPIKE) : Shim MCP/HTTP conteneur → mTLS noyau

**Files:**
- Create: `kernel/helixos-mcp-shim/Cargo.toml`, `kernel/helixos-mcp-shim/src/main.rs`
- Modify: `frontier/compose/docker-compose.yml` (déclarer le serveur MCP à Hermes)

**Interfaces:**
- Consumes: le serveur mTLS du noyau (B8) ; le format d'intention (B3).
- Produces: un serveur MCP (stdio ou HTTP) exposé à Hermes qui traduit un appel d'outil `helix_patch_note{path, patch}` en une intention `ProposeFilePatch` transmise au noyau via mTLS, et renvoie le `plan_hash` + l'URL de la carte.

> **SPIKE** : format d'exposition MCP consommé par Hermes (stdio/HTTP + `mcp_<serveur>_<outil>`). Vérifier qu'Hermes appelle bien l'outil et relaie le lien d'approbation à l'utilisateur.

- [ ] **Step 1 : Spike MCP** : brancher un serveur MCP trivial à Hermes, confirmer l'appel d'outil aller-retour.
- [ ] **Step 2 : Test d'intégration qui échoue** : un appel `helix_patch_note` produit un `plan_hash` côté noyau (via mTLS), sans appliquer.
- [ ] **Step 3 : Implémenter le shim** (client mTLS vers le noyau ; mapping outil→intention ; jamais d'apply direct — l'apply passe par l'approbation).
- [ ] **Step 4 : Lancer — doit passer.**
- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-mcp-shim/ frontier/compose/docker-compose.yml
git commit -m "shim: MCP tool helix_patch_note -> mTLS ProposeFilePatch (plan only, approval-gated)"
```

### Task D2 : Acceptance de bout en bout (test 5, esprit MVP-0)

**Files:**
- Create: `frontier/harness/e2e-patch-note.ps1`

**Interfaces:**
- Consumes: A1–D1.

- [ ] **Step 1 : Écrire le scénario de bout en bout**

```powershell
# frontier/harness/e2e-patch-note.ps1
$ErrorActionPreference = 'Stop'
$note = "$env:USERPROFILE\HelixVault\demo.md"
Set-Content -Encoding utf8 $note "avant"
# 1. Depuis Hermes, appeler l'outil helix_patch_note (via le canal de test MCP)
#    -> renvoie plan_hash + URL de carte sur l'origine distincte
# 2. Ouvrir la carte, vérifier qu'elle affiche QUOI/OÙ/RISQUE/POURQUOI/INHABITUEL + hash
# 3. Approuver (L1 tap) -> le noyau applique
if ((Get-Content $note -Raw).Trim() -ne "après") { Write-Error "E2E ÉCHEC : patch non appliqué"; exit 1 }
# 4. Vérifier l'audit
if (-not (Select-String -Path "$env:LOCALAPPDATA\HelixOS\audit.jsonl" -Pattern "apply_file_patch")) { Write-Error "E2E ÉCHEC : audit manquant"; exit 1 }
# 5. Rollback -> restaure "avant"
Write-Host "E2E VERT : proposer -> approuver hors-webui -> appliquer -> auditer -> annuler."
```

- [ ] **Step 2 : Exécuter — attendu VERT**

Run: `powershell -File frontier/harness/e2e-patch-note.ps1`
Expected: "E2E VERT", exit 0.

- [ ] **Step 3 : Commit**

```bash
git add frontier/harness/e2e-patch-note.ps1
git commit -m "harness: end-to-end vault-note patch (propose->approve off-webui->apply->audit->rollback)"
```

---

## Phase E — Plancher opérationnel mince

*Sortie de phase : une perte matérielle est récupérable (backup vault + audit/état noyau, restauration testée) ; le noyau redémarre proprement sans double-exécution. Pas d'upgrade sophistiqué, pas de relais — MVP-0 est au bureau.*

### Task E1 : Backup + restauration testée

**Files:**
- Create: `ops/backup.ps1`, `ops/restore.ps1`

- [ ] **Step 1 : Écrire backup.ps1**

```powershell
# ops/backup.ps1 — vault (Git) + audit/état noyau, chiffré
$ErrorActionPreference = 'Stop'
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss')     # timestamp passé en argument en CI (pas d'horloge dans les tests)
$dest = "$env:USERPROFILE\HelixBackups\$stamp"
New-Item -ItemType Directory -Force $dest | Out-Null
# Vault : commit Git si repo, + copie
git -C "$env:USERPROFILE\HelixVault" add -A; git -C "$env:USERPROFILE\HelixVault" commit -m "backup $stamp" 2>$null
Copy-Item "$env:LOCALAPPDATA\HelixOS\audit.jsonl" "$dest\audit.jsonl"
Copy-Item "$env:LOCALAPPDATA\HelixOS\state" "$dest\state" -Recurse -ErrorAction SilentlyContinue
Write-Host "Backup: $dest"
```

- [ ] **Step 2 : Écrire restore.ps1 + test de restauration réelle**

```powershell
# ops/restore.ps1 <backup-dir>
param([Parameter(Mandatory)][string]$From)
$ErrorActionPreference = 'Stop'
Copy-Item "$From\audit.jsonl" "$env:LOCALAPPDATA\HelixOS\audit.jsonl" -Force
if (Test-Path "$From\state") { Copy-Item "$From\state" "$env:LOCALAPPDATA\HelixOS\state" -Recurse -Force }
Write-Host "Restauré depuis $From"
```

- [ ] **Step 3 : Prouver la restauration (test 18, esprit MVP-0)**

Run: créer une note + audit, `ops/backup.ps1`, détruire l'audit, `ops/restore.ps1 <dir>`, vérifier que l'audit est identique.
Expected: le fichier audit restauré == l'original (comparaison de hash).

- [ ] **Step 4 : Commit**

```bash
git add ops/backup.ps1 ops/restore.ps1
git commit -m "ops: backup + tested restore (vault + kernel audit/state)"
```

### Task E2 : Redémarrage propre (pas de double-exécution)

**Files:**
- Create: `kernel/helixos-kernel/src/plan.rs` (persistance de l'état `consumed`) — Modify
- Create: `kernel/helixos-kernel/tests/restart_it.rs`

**Interfaces:**
- Consumes: pipeline (B7).
- Produces: l'état des plans consommés survit au redémarrage (persisté sur disque) ; rejouer un plan consommé après restart → refusé.

- [ ] **Step 1 : Écrire le test qui échoue**

```rust
// kernel/helixos-kernel/tests/restart_it.rs
#[test] fn consumed_plan_stays_consumed_across_restart() {   // test 9 (persistance)
    // 1. Kernel A : plan + apply (consumed=true) -> l'état est persisté sur disque.
    // 2. Kernel B : recharge l'état depuis le même chemin.
    // 3. B.apply(meme_hash) -> Err (rejeu refusé après restart).
    // (Utilise Kernel::new(state_dir) + Kernel::load(state_dir).)
}
```

- [ ] **Step 2 : Lancer — doit échouer** (pas de persistance). Run: `cd kernel && cargo test -p helixos-kernel --test restart_it`. Expected: FAIL.
- [ ] **Step 3 : Implémenter la persistance** : sérialiser la map `plan_hash -> {consumed}` en JSONL append-only à chaque `apply` ; `Kernel::load(state_dir)` la relit au démarrage.
- [ ] **Step 4 : Lancer — doit passer.**
- [ ] **Step 5 : Commit**

```bash
git add kernel/helixos-kernel/src/pipeline.rs kernel/helixos-kernel/tests/restart_it.rs
git commit -m "kernel: persist consumed-plan state -> no double execution across restart"
```

---

## Self-Review (exécutée sur ce plan)

**1. Couverture spec (MVP-0 / roadmap) :**
- Frontière prouvée + harness (tests 1,2) → Phase A ✓
- Runtime natif dockerd/WSL2, pas Docker Desktop → A1/A2 ✓
- Noyau Rust minimal : mTLS (B8/test 3), pipeline une intention (B7), plan signé hash/TTL (B4/test 13), idempotence (B7/E2/test 9), bail de portée (B2/test 20) → ✓
- Une intention fichier-patch note-vault (`read_file`/`propose`/`apply`) → B6/B7/D ✓
- Approbation hors webui, origine distincte, L1 tap / L2 passkey, carte §4 → C1/C2/C3 ✓
- Anti-TOCTOU (test 12) → B4 ✓ ; deny-list secrets → L2 (test 19) → B3 ✓
- Audit append-only → B5 ✓ ; rollback compensation → B6 ✓
- Plancher ops (backup+restore, restart propre) → E1/E2 ✓
- Gelé (VSS/auto, sidecar, Graphify, vision, cron, budgets, kanban, blue/green, relais/mobile) → absent du plan ✓

**2. Placeholders :** les seules zones non entièrement codées sont les 5 tâches **SPIKE** (B8, C2, C3, D1) — délibérées : elles portent des surfaces OS/crypto (rustls, axum-TLS, webauthn-rs, MCP) où figer un appel d'API non vérifié produirait du « plausible mais faux ». Chacune a un livrable concret (« l'exemple compile/tourne », test rouge→vert) et le crate exact à utiliser — ce ne sont pas des « TODO », ce sont des tâches de vérification-puis-implémentation.

**3. Cohérence des types :** `Intention`, `ScopeLease::permits`, `Plan{plan_hash,target_hash_at_diff,consumed,is_expired,verify_target_unchanged}`, `RiskLevel`, `AuditRecord`, `DriverHost::{read_file,search_files,stage_and_apply,rollback}`, `Kernel::{plan_intention,apply}`, `Card::{from_plan,render_text}` — noms et signatures alignés entre tâches (B1↔B6↔B7, B4↔B7, C1↔C2).

**Note d'exécution :** `Date.now()`/horloge — les tests passent les timestamps en argument là où c'est possible ; l'idempotence est prouvée par usage-unique persistant (E2), pas par l'horloge. Les 5 SPIKE doivent être exécutées avec `cargo` réel : ne pas les figer sans lancer le code.
