# @lexdocia/collecte-crypto

Primitives de chiffrement hybride (X25519 + ML-KEM-768 + XChaCha20-Poly1305) partagées entre
deux repos séparés :

- **lexdocia-collect** (`apps/portail`) — chiffre les documents déposés par le client, dans
  le navigateur, avant upload.
- **PieceMaster** (section Collecter) — déchiffre les documents récupérés, localement sur le
  poste de l'avocat.

Extrait dans son propre repo (plutôt que dupliqué dans les deux) pour garantir qu'un seul et
même code fait le chiffrement et le déchiffrement — un écart d'implémentation entre les deux
casserait le flux.

Aucune primitive cryptographique "maison" : uniquement libsodium (symétrique + X25519) et
`@noble/post-quantum` (ML-KEM-768, FIPS 203).

## Consommation

En dépendance git directe (pas de registre npm) :

```json
"@lexdocia/collecte-crypto": "github:farsightbs/lexdocia-collecte-crypto#v0.0.1"
```

Le script `prepare` construit `dist/` automatiquement à l'installation (npm et pnpm
l'exécutent tous les deux pour une dépendance git).

## Développement

```bash
npm install
npm run build
npm test
```
