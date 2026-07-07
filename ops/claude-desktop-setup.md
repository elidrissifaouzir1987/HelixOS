# Piloter HelixOS depuis Claude Desktop

Objectif : demander en langage naturel (« complète ma note d'idées », « reformule ce paragraphe »)
et laisser HelixOS te faire **approuver** chaque modification avant qu'elle s'applique.

## Prérequis
- Les binaires sont compilés : `cd kernel && cargo build` (crée `kernel/target/debug/*.exe`).
- Claude Desktop est installé.

## 1. Démarre le service HelixOS (à laisser tourner)
Dans une fenêtre PowerShell, depuis le dossier `HelixOS` :
```powershell
.\ops\helix-up.ps1                       # vault par défaut : %USERPROFILE%\HelixVault
# ou :  .\ops\helix-up.ps1 -Vault "D:\MesNotes"
```
Laisse cette fenêtre ouverte : c'est le « gardien » qui tourne (serveur mTLS + page d'approbation).
Mets tes notes (fichiers `.txt` / `.md`) dans le dossier vault.

## 2. Branche le shim dans Claude Desktop
Ouvre (ou crée) le fichier de config de Claude Desktop :
`%APPDATA%\Claude\claude_desktop_config.json`

et ajoute le serveur `helixos` (fusionne avec ce qui existe déjà) — **adapte les chemins** si besoin :
```json
{
  "mcpServers": {
    "helixos": {
      "command": "C:\\Users\\elidr\\Documents\\Claude\\HelixOS\\kernel\\target\\debug\\helixos-mcp-shim.exe",
      "env": {
        "HELIX_KERNEL_ADDR": "127.0.0.1:8443",
        "HELIX_APPROVAL_ORIGIN": "https://localhost:8600",
        "HELIX_MTLS_CA": "C:\\Users\\elidr\\.helixos\\certs\\ca.pem",
        "HELIX_MTLS_CLIENT_CERT": "C:\\Users\\elidr\\.helixos\\certs\\client.pem",
        "HELIX_MTLS_CLIENT_KEY": "C:\\Users\\elidr\\.helixos\\certs\\client.key",
        "HELIX_KERNEL_SERVER_NAME": "localhost"
      }
    }
  }
}
```
Puis **redémarre Claude Desktop**. L'outil `helix_patch_note` apparaît (icône outils/MCP).

## 3. Utilise-le
Demande par exemple : *« Avec l'outil helix_patch_note, réécris ma note
`C:\Users\elidr\HelixVault\idees.txt` pour y ajouter trois idées. »*
Claude te renverra un **lien d'approbation** (`https://localhost:8600/op/…`).
Ouvre-le → tu vois la carte (quoi / où / risque / pourquoi) → clique **Approuver** → la note change.

## À savoir (MVP-0)
- Le noyau ne peut toucher **que** les fichiers du dossier vault (règle de portée).
- Le patch **remplace tout le contenu** de la note (pas encore de modif ligne par ligne).
- Le navigateur affichera un **avertissement TLS** (la CA est privée) : ajoute
  `%USERPROFILE%\.helixos\certs\ca.pem` à ta confiance Windows, ou clique-à-travers.
- Seul le niveau **L1** (tap) est actif. Le **L2** (validation par passkey, pour les actions
  sensibles) n'est pas encore branché.

## Sans Claude Desktop
Tu peux rejouer la boucle à la main (le service doit tourner — étape 1) :
```powershell
python .\ops\helix_patch.py --note "$env:USERPROFILE\HelixVault\idees.txt" --content "nouveau contenu" --approve
# sans --approve : le script te donne l'URL a ouvrir dans le navigateur pour approuver toi-meme
```
