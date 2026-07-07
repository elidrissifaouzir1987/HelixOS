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

# --- Test 2 : le conteneur ne doit PAS joindre un port hôte non prévu ---
# Port RDP (3389) sur la gateway WSL comme sonde d'un service hôte quelconque.
GW=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
if [ -n "${GW:-}" ]; then
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w3 "$GW" 3389 2>/dev/null; then note "LEAK 2: port hôte 3389 joignable ($GW)"; leak=1; else note "OK 2: port hôte non prévu bloqué ($GW:3389)"; fi
  else
    # /dev/tcp (bash) en repli si nc absent.
    if timeout 3 sh -c ": >/dev/tcp/$GW/3389" 2>/dev/null; then note "LEAK 2: port hôte 3389 joignable ($GW)"; leak=1; else note "OK 2: port hôte non prévu bloqué ($GW:3389)"; fi
  fi
else
  note "?? 2: gateway introuvable (ip route) — vérifier manuellement"
fi

if [ "$leak" -eq 0 ]; then echo "FRONTIERE-ETANCHE"; else echo "FRONTIERE-PERCEE"; fi
exit $leak
