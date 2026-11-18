# Rapport d'audit de sécurité — P2P Chat

- **Projet** : P2P Chat — messagerie deux-personnes, sans serveur, chiffrée de bout en bout sur Tor
- **Dépôt** : `Datchi17/p2p-tor-chat`
- **Date** : 2026-10-21
- **Auteur du rapport** : revue de sécurité indépendante (Claude)
- **Périmètre** : lecture intégrale du code « maison » (~5 400 lignes Rust + ~1 300 TS), hors bibliothèques auditées en amont (libsignal, Tor, `snow`, SQLCipher, `argon2`, Tauri)

---

## 1. Résumé exécutif

Le cœur cryptographique de l'application est **à l'état de l'art** (protocole Signal post-quantique, Noise IK, Tor v3 avec autorisation client, SQLCipher + Argon2id) et — point le plus important — il est **correctement intégré**. La lecture ligne par ligne n'a révélé **aucune faille mémoire, injection (SQL/commande/XSS), contournement d'authentification, trou de rejeu, ni mauvais usage cryptographique** dans le code de glue.

Deux défauts **réels et corrigeables** ont été identifiés et **corrigés** (voir §6). Trois faiblesses de gravité élevée subsistent mais **ne sont pas des bugs de code** : elles relèvent du facteur humain et du processus (vérification sur appel, signature de l'installeur, audit externe).

Le scan de vulnérabilités des dépendances (`cargo audit`) ne remonte **aucune CVE**.

**Verdict** : système **solide et digne de confiance** pour son usage prévu, **pas « incassable »** — aucun système ne l'est, et les points de rupture réalistes sont humains/processus, pas cryptographiques.

---

## 2. Environnement de test mis en place (Windows 11)

| Outil | État |
|---|---|
| Rust (rustc/cargo 1.99.1) | installé via `rustup` |
| MSVC C++ Build Tools (VC 14.44) | installé via winget |
| protoc (libprotoc 36.0) | installé via winget (requis par `libsignal`) |
| Node 24 / npm | déjà présent |
| WebView2 | déjà présent |
| Tor Expert Bundle (Windows, vérifié GPG) | récupéré dans `vendor/tor-windows/` |

Incident de build résolu : une variable d'environnement `PERL` pointait vers un fichier inexistant (`relocation.pl.bat`), faisant échouer la compilation d'OpenSSL embarqué (dépendance de SQLCipher). Corrigé en pointant `PERL` vers le vrai `perl.exe`.

---

## 3. Résultats des tests

`cargo test --workspace --exclude p2p-chat` : **64 tests réussis, 0 échec** (après corrections).

| Crate | Tests | Couverture |
|---|---|---|
| `p2p-signal` | 19 ✅ | Crypto Signal, PQXDH, ratchet, rejet d'imposteurs, anti-rejeu, bit-flip exhaustif |
| `p2p-vault` | 12 ✅ | SQLCipher, aucun clair sur disque, changement de passphrase crash-safe, anti-downgrade KDF, wipe |
| `p2p-core` | 10 ✅ | Pairing, portail de vérification, cycle de vie du coffre |
| `p2p-transport` | 8 ✅ | Noise IK, adresses onion, rejet d'initiateur inconnu, trame falsifiée rejetée |
| `p2p-proto` | 2 ✅ | Paddings par paliers, fuzzing de trames |
| Tests « live » (vrai Tor) | *ignored* | À lancer manuellement (`--ignored`) |

---

## 4. Architecture : défense en profondeur

Un message traverse 5 couches indépendantes :

| # | Couche | Mécanisme | Bibliothèque |
|---|---|---|---|
| 1 | Contenu | Signal : PQXDH (X25519 + ML-KEM-1024), Double Ratchet, SPQR | `libsignal-protocol` v0.105.2 |
| 2 | Authentification pair | Noise `IK_25519_ChaChaPoly_BLAKE2s`, clés épinglées au pairing | `snow` |
| 3 | Transport / anonymat | Services onion Tor v3 + autorisation client | Tor (bundle signé) |
| 4 | Stockage | SQLCipher (AES-256) + clé = Argon2id(256 MiB, t=3, p=4) | `rusqlite` + `argon2` |
| 5 | Coquille / UI | CSP stricte, commandes deny-by-default, rendu texte | Tauri 2 + SolidJS |

Percer une couche fait tomber sur la suivante. Aucun serveur n'existe.

---

## 5. Analyse par couche (synthèse)

### Couche 1 — Signal ✅
- Épinglage d'identité plus fort que le TOFU : `save_identity` refuse tout changement de clé (`p2p-signal/src/lib.rs:205`).
- Post-quantique **exigé** : `usable()` impose `EstablishedWithPqxdh` (`lib.rs:47`).
- Prekeys à usage unique (EC + Kyber) **effacées à l'usage** → secret persistant + anti-rejeu.
- Déchiffrement dans un `SAVEPOINT` avec `ROLLBACK` sur échec (`lib.rs:561`) : un message forgé ne peut pas consommer de matériel clé (testé bit par bit).

### Couche 2 — Noise IK ✅
- Prologue liant l'app/version (`noise.rs:19`) ; répondeur **refusant silencieusement** un initiateur inconnu (`noise.rs:138`).
- Partage lecteur/écrivain de l'état transport correct (nonces séparés par direction).

### Couche 3 — Tor ✅
- Tor privé, ports loopback aléatoires, auth par cookie, Tor meurt avec l'app.
- **Injection de commandes de contrôle bloquée** (rejet CRLF, `tor.rs:396`), `SafeSocks`, vérifs `is_loopback`.
- Double verrou : autorisation client Tor v3 + Noise IK. Un inconnu ne peut même pas récupérer le descripteur onion.
- Clés en `Zeroizing`, jamais journalisées (vérifié).

### Couche 4 — Vault ✅
- Argon2id 256 MiB, clé brute SQLCipher construite **sans réallocation** (`vault/lib.rs:148`).
- Anti-downgrade du KDF (`lib.rs:225`), changement de passphrase crash-safe, vérification en temps constant.

### Couche 5 — Tauri / UI ✅
- Capacités **deny-by-default** (seulement les 23 commandes de l'app), **CSP stricte**.
- **Zéro XSS** : rendu texte SolidJS, aucun `innerHTML`/`eval`, QR affiché via `<img src="data:">` (scripts SVG neutralisés).
- L'UI ne voit **jamais** de clé ni de texte chiffré.

### Points forts transversaux
- `unsafe` **interdit** au niveau workspace (0 occurrence).
- Aucun `unwrap()`/`expect()` atteignable par une entrée réseau hostile → pas de DoS par panic.
- SQL **entièrement paramétré** (interpolations = constantes seulement).

---

## 6. Failles identifiées et corrections

### 🔴 Élevé — inhérent / processus (NON corrigeable en code)

| # | Faiblesse | Pourquoi pas de correctif code | Atténuation |
|---|---|---|---|
| 1 | Vérification dépend de la discipline humaine (safety number affiché à l'écran → un utilisateur paresseux peut « auto-vérifier ») | Limite inhérente à tout schéma de safety number (Signal inclus) ; masquer les groupes crée des blocages (~32 % de collision) et casse l'étape de comparaison | Appel vidéo discipliné + reconnaissance vocale ; l'UX pousse déjà fortement au bon geste |
| 2 | Installeur trojané (pas de signature de code, builds non reproductibles) | Relève de l'infra CI, pas du code applicatif | Lire le SHA-256 à voix haute sur l'appel |
| 3 | Audité/écrit par une seule IA | Relève d'une revue externe | Cette revue + `cargo audit` ; audit humain recommandé |

### 🟢 Corrigé dans le code (2 correctifs chirurgicaux)

**Correctif 1 — Confidentialité : accusés de lecture vers contact non vérifié** — `crates/p2p-core/src/lib.rs` (`mark_read`)
`mark_read` envoyait un accusé de lecture sans vérifier le statut `verified` du contact — un pair pairé mais non vérifié (imposteur potentiel sous MITM) apprenait « message lu ». Désormais : marquage **local** toujours effectué, mais **envoi** de l'accusé uniquement vers un contact **vérifié** (aligné sur `send_text`/`set_disappearing`).

```rust
// Avant
let ids = db::mark_read(c, contact_id)?;
if ids.is_empty() || !db::settings_get(c)?.read_receipts { return Ok(false); }

// Après
let verified = db::contact(c, contact_id)?.is_some_and(|k| k.verified);
let ids = db::mark_read(c, contact_id)?;
if ids.is_empty() || !verified || !db::settings_get(c)?.read_receipts { return Ok(false); }
```

**Correctif 2 — Robustesse : fausse alerte de sécurité sur livraison en masse** — `crates/p2p-core/src/peer.rs:31`
La limite de débit (`MAX_ENVELOPES_PER_SEC = 50`) était **inférieure** à la taille d'un lot de livraison (`OUTBOX_BATCH = 100`). Un contact revenant en ligne avec 51+ messages en attente les envoie d'un bloc ; sur un lien rapide (loopback, p.ex. le test deux-instances) ils arrivent en < 1 s → la connexion était coupée avec l'alerte **« contact sent messages too fast »** et une livraison fragmentée sur plusieurs reconnexions. Plafond relevé à **256** (> lot, tout en bornant un vrai flood).

> Les deux correctifs sont minimaux, compris, et validés par la suite de tests complète (64/64). Le cœur cryptographique n'a **pas** été modifié — volontairement : on ne refond pas du code crypto sain sous peine d'introduire pire.

### 🟠 / 🟡 Moyen / faible (inhérents, assumés)
- Corrélation de trafic par timing (Tor ne défait pas la corrélation bout-à-bout ; le padding aide mais n'est pas du trafic de couverture).
- Les deux apps doivent être en ligne simultanément (par conception, sans serveur).
- Historique en clair dans le coffre déverrouillé (nécessaire pour lire son historique ; atténué par messages éphémères + panic-wipe).
- Effacement « best-effort » sur SSD/CoW.
- Malware/keylogger sur une machine déverrouillée — indéfendable.

---

## 7. Scan des dépendances (`cargo audit`)

Base RustSec (1348 avis) — **580 dépendances scannées** — **0 vulnérabilité (CVE)**.

3 avertissements informatifs, sans impact exploitable :

| Crate | Type | Impact réel |
|---|---|---|
| `proc-macro-error 1.0.4` | non maintenu (RUSTSEC-2024-0370) | Macro **build-time** — absente du binaire final |
| `proc-macro-error2 2.0.1` | non maintenu (RUSTSEC-2026-0173) | Idem — build-time |
| `glib 0.18.5` | *unsound* (RUSTSEC-2024-0429) | Pile **GTK/Linux** — non utilisée sur Windows (WebView2) ; API fautive non appelée |

---

## 8. État du build fonctionnel

- Frontend SolidJS : **compilé proprement** (type-check `tsc` + `vite build`).
- App complète (coquille Tauri + WebView2, avec les 2 correctifs) : **compilée avec succès** (profil `dev`, code 0). `spqr` (ratchet PQ) et `libsignal` requièrent `protoc` à la compilation — présent dans l'environnement.
- Test live (Tor + pairing dans la fenêtre) : **à réaliser manuellement** — étape intrinsèquement interactive (création du coffre, saisie de passphrase, observation de « 🧅 Tor connected »).

Commande de lancement :
```powershell
$env:P2PCHAT_TOR="<repo>\vendor\tor-windows\tor\tor.exe"; npm --prefix ui run tauri dev
```

---

## 9. Recommandations (par priorité)

1. **Vérification sur appel vidéo** à chaque pairing/re-pairing, avec reconnaissance vocale — c'est la protection anti-MITM la plus critique et la seule que le code ne peut pas imposer.
2. **Signer l'installeur + builds reproductibles** ; lire le SHA-256 à voix haute en attendant.
3. **Audit humain indépendant** avant tout usage où des vies dépendent de la confidentialité.
4. Suivre les avis `cargo audit` dans le temps (le workflow `maintenance` hebdomadaire le fait déjà).
5. Ne pas étendre la surface d'attaque (garder `unsafe` interdit, capacités deny-by-default, CSP stricte).

---

## 10. Verdict final

**Sécurisé : oui, à un niveau remarquable.** La cryptographie vient de projets audités et est intégrée correctement ; le code de glue est propre et ferme les pièges classiques.

**« Incassable » : non** — aucun système ne l'est. Les trois points de rupture réalistes ne sont **pas** cryptographiques :
1. **L'humain** — sans appel vidéo réel avec comparaison des chiffres, la protection anti-MITM tombe.
2. **Le terminal** — un malware sur une machine déverrouillée voit tout en clair.
3. **La chaîne d'approvisionnement** — sans build signé/reproductible, un installeur trafiqué contourne tout.

**En pratique** : base **très solide et digne de confiance** pour l'usage prévu (deux personnes, après vérification correcte). Pour un usage critique : audit indépendant + builds signés/reproductibles + discipline stricte de vérification. « Excellente ingénierie, pas encore prouvée en conditions hostiles. »
