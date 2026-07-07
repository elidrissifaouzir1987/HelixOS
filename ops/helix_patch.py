#!/usr/bin/env python3
"""HelixOS — proposer (et éventuellement approuver) une modification de note, via le shim MCP + le noyau mTLS.

Le noyau doit tourner (lance d'abord `ops\\helix-up.ps1` dans une autre fenêtre).

Exemples :
  # proposer une modif et te laisser approuver dans le navigateur :
  python ops/helix_patch.py --note "%USERPROFILE%\\HelixVault\\idees.txt" --content-file nouveau.txt

  # proposer ET approuver automatiquement (démo, niveau L1) :
  python ops/helix_patch.py --note "%USERPROFILE%\\HelixVault\\idees.txt" --content "nouveau contenu" --approve

Sans --approve : le script imprime l'URL d'approbation ; ouvre-la dans ton navigateur et clique APPROUVER.
(Le contenu remplace intégralement la note — c'est le comportement du MVP-0.)
"""
import os, sys, json, ssl, http.client, subprocess, argparse, pathlib

def main():
    ap = argparse.ArgumentParser(description="Proposer/approuver un patch de note via HelixOS.")
    ap.add_argument("--note", required=True, help="Chemin du fichier note (doit être dans le vault).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--content", help="Nouveau contenu (texte).")
    g.add_argument("--content-file", help="Fichier dont le contenu devient le nouveau contenu de la note.")
    ap.add_argument("--cert-dir", default=os.path.join(os.path.expanduser("~"), ".helixos", "certs"))
    ap.add_argument("--kernel-addr", default=os.environ.get("HELIX_KERNEL_ADDR", "127.0.0.1:8443"))
    ap.add_argument("--approval-origin", default=os.environ.get("HELIX_APPROVAL_ORIGIN", "https://localhost:8600"))
    ap.add_argument("--server-name", default=os.environ.get("HELIX_KERNEL_SERVER_NAME", "localhost"))
    ap.add_argument("--shim", default=str(pathlib.Path(__file__).resolve().parent.parent /
                                          "kernel" / "target" / "debug" / "helixos-mcp-shim.exe"))
    ap.add_argument("--approve", action="store_true", help="Auto-approuve (L1) après la proposition (démo).")
    a = ap.parse_args()

    content = a.content if a.content is not None else open(a.content_file, encoding="utf-8").read()
    cd = a.cert_dir
    env = dict(os.environ,
               HELIX_KERNEL_ADDR=a.kernel_addr, HELIX_APPROVAL_ORIGIN=a.approval_origin,
               HELIX_MTLS_CA=os.path.join(cd, "ca.pem"),
               HELIX_MTLS_CLIENT_CERT=os.path.join(cd, "client.pem"),
               HELIX_MTLS_CLIENT_KEY=os.path.join(cd, "client.key"),
               HELIX_KERNEL_SERVER_NAME=a.server_name)

    req1 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "helix_patch", "version": "0"}}})
    req2 = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "helix_patch_note",
                                  "arguments": {"path": a.note, "patch": content}}})
    p = subprocess.run([a.shim], input=(req1 + "\n" + req2 + "\n").encode(),
                       capture_output=True, env=env)

    plan_hash, err = None, None
    for line in p.stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if msg.get("id") == 2:
            res = msg.get("result", {})
            if res.get("isError"):
                err = (res.get("content") or [{}])[0].get("text", "erreur")
            else:
                plan_hash = res["structuredContent"]["plan_hash"]
    if not plan_hash:
        print("Echec de la proposition :", err or p.stderr.decode(errors='replace')[:300])
        sys.exit(1)

    url = f"{a.approval_origin}/op/{plan_hash}"
    print("Patch PROPOSE (non applique).")
    print("  plan_hash :", plan_hash)
    print("  approbation :", url)
    if not a.approve:
        print("\n-> Ouvre cette URL dans ton navigateur et clique APPROUVER.")
        print("   (Ton navigateur affichera un avertissement TLS car la CA est privee :")
        print("    ajoute", os.path.join(cd, "ca.pem"), "a ta confiance, ou clique-a-travers.)")
        return

    ctx = ssl.create_default_context(cafile=os.path.join(cd, "ca.pem"))
    hostport = a.approval_origin.split("://", 1)[1]
    host, port = hostport.split(":"); port = int(port)
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    conn.request("POST", f"/op/{plan_hash}/approve")
    r = conn.getresponse(); body = r.read().decode(errors="replace")
    if r.status == 200:
        print("APPROUVE (L1) -> applique.", body[:120])
    else:
        print("Refus/erreur d'approbation :", r.status, body[:200])

if __name__ == "__main__":
    main()
