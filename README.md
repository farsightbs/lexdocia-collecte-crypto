# @lexdocia/collecte-crypto

Primitives de chiffrement hybride (KEM X-Wing = X25519 + ML-KEM-768, puis XChaCha20-Poly1305) partagées entre
deux repos séparés :

- **lexdocia-collect** (`apps/portail`) — chiffre les documents déposés par le client, dans
  le navigateur, avant upload.
- **PieceMaster** (section Collecter) — déchiffre les documents récupérés, localement sur le
  poste de l'avocat.

Extrait dans son propre repo (plutôt que dupliqué dans les deux) pour garantir qu'un seul et
même code fait le chiffrement et le déchiffrement — un écart d'implémentation entre les deux
casserait le flux.

Aucune primitive cryptographique "maison" : uniquement libsodium (symétrique : XChaCha20-Poly1305,
BLAKE2b, Argon2id) et `@noble/post-quantum` (KEM hybride **X-Wing**, `ml_kem768_x25519` :
ML-KEM-768 FIPS 203 + X25519, tel que spécifié par `draft-connolly-cfrg-xwing-kem`). Le combineur des
deux secrets est celui de X-Wing, testé contre les vecteurs officiels du draft (`src/xwing-kat.test.ts`) :
ce package ne recompose rien.

## Format (version 2)

- Clé publique de l'avocat/du client : 1216 octets (X-Wing). Clé privée : graine de 32 octets, jamais transmise.
- `cle_fichier_encapsulee` : `version(1) ‖ ciphertext X-Wing(1120) ‖ nonce(24) ‖ clé de fichier enveloppée(48)`.
  La clé de fichier est enveloppée par XChaCha20-Poly1305 avec le secret X-Wing, et le ciphertext X-Wing
  est lié comme donnée authentifiée (AAD).
- La version 1 (hybride X25519 + ML-KEM combiné par BLAKE2b) n'est **plus lue** : les données v1 ont été
  remises à zéro lors de la migration. Une enveloppe de version 1 est rejetée (`InvalidEnvelopeError`).
- X-Wing est encore un draft CFRG : si la forme finale change, on passera par un nouveau `FORMAT_VERSION`.

## Consommation

En dépendance git directe (pas de registre npm) :

```json
"@lexdocia/collecte-crypto": "github:farsightbs/lexdocia-collecte-crypto#v0.2.0"
```

`dist/` est **committé** dans ce repo (exception volontaire à la convention habituelle), et
il n'y a **pas** de script `prepare`/`postinstall` : npm ≥ 11.17 bloque par défaut le
`prepare` d'une dépendance tierce (gate `allow-scripts`) et pnpm bloque carrément
l'installation d'une dépendance git avec un script de build tant qu'elle n'est pas dans
`allowBuilds` (et la clé qu'il demande est qualifiée par le hash de commit résolu — elle
changerait à chaque bump de version). Ne compter sur aucun script de build à l'installation
et committer `dist/` directement évite les deux problèmes, quel que soit le gestionnaire de
paquets ou sa version.

## Développement

```bash
npm install
npm run build
npm test
```

Après une modification de `src/` : `npm run build`, committer `src/` **et** `dist/`
ensemble, bump la version dans `package.json`, tag (`git tag vX.Y.Z && git push --tags`) —
puis mettre à jour la référence `#vX.Y.Z` dans les deux consommateurs
(`lexdocia-collect/apps/{api,portail}/package.json`, `piecemaster/package.json`).
