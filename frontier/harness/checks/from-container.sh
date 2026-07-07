#!/bin/sh
# Tentatives de CONTOURNEMENT de la frontière, exécutées DANS le conteneur Hermes.
# Convention : exit 0 = frontière ÉTANCHE (tous les contournements ont ÉCHOUÉ) ;
#              exit 1 = frontière PERCÉE (au moins un contournement a RÉUSSI = une FUITE).
# Le harness doit rester VERT en durci, et virer au ROUGE si on relâche un réglage (test de régression).
set -u
leak=0
note() { echo "  $1"; }

# --- Test 1 : le conteneur ne doit PAS atteindre l'hôte (filesystem / vault / binaires) ---
# 1a : filesystem hôte Windows via /mnt/c (fermé par automount=off).
if ls /mnt/c >/dev/null 2>&1; then note "LEAK 1a: /mnt/c lisible (automount actif)"; leak=1; else note "OK 1a: /mnt/c inaccessible"; fi
# 1b : vault inscriptible (doit être RO — toute mutation passe par le noyau).
if touch /vault/.breach 2>/dev/null; then note "LEAK 1b: vault inscriptible depuis le conteneur"; rm -f /vault/.breach 2>/dev/null; leak=1; else note "OK 1b: vault en lecture seule"; fi
# 1c : exécuter un binaire Windows via l'interop /init (fermé par interop=off).
if [ -e /init ] && /init /mnt/c/Windows/System32/cmd.exe /c echo x >/dev/null 2>&1; then note "LEAK 1c: interop Windows actif"; leak=1; else note "OK 1c: interop désactivé"; fi
# 1d : socket Docker monté (= root sur l'hôte de la distro).
if [ -S /var/run/docker.sock ]; then note "LEAK 1d: /var/run/docker.sock monté dans le conteneur"; leak=1; else note "OK 1d: pas de docker.sock"; fi

# --- Test 2 : aucune SORTIE réseau (ni internet, ni port hôte) ---
# Décisif quel que soit le routage : on tente une cible externe fixe ET la gateway WSL.
# En durci (réseau `internal`), les deux doivent ÉCHOUER.
egress=0
if nc -w2 1.1.1.1 53 </dev/null >/dev/null 2>&1; then egress=1; fi          # internet (DNS/TCP)
GW=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
if [ -n "${GW:-}" ] && nc -w2 "$GW" 3389 </dev/null >/dev/null 2>&1; then egress=1; fi   # port hôte quelconque
if [ "$egress" -eq 1 ]; then note "LEAK 2: sortie réseau possible (internet/hôte)"; leak=1; else note "OK 2: aucune sortie réseau"; fi

if [ "$leak" -eq 0 ]; then echo "FRONTIERE-ETANCHE"; else echo "FRONTIERE-PERCEE"; fi
exit $leak
