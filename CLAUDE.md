# lexdocia-collecte-crypto

Primitives de chiffrement hybride (KEM X-Wing = X25519 + ML-KEM-768, puis XChaCha20-Poly1305) partagées entre le portail `lexdocia-collect` (chiffrement navigateur) et PieceMaster (déchiffrement). Voir `README.md`.

## Règles

- Aucune primitive cryptographique "maison" : libsodium et `@noble/post-quantum` uniquement. Tout changement de librairie crypto exige une confirmation explicite.
- **Dépendances** : toute introduction, suppression ou mise à jour de librairie (Dependabot compris) impose de mettre à jour `specs/third-party-libraries.md` dans la même PR — règle complète dans `specs/dependency-management.md` (à lire avant de toucher à `package.json` ou au lockfile). `node scripts/check-licenses.mjs` le vérifie en CI.
- `dist/` est committé : après modification de `src/`, rebuild, commit `src/` + `dist/`, bump de version + tag, puis mise à jour de la référence `#vX.Y.Z` dans `lexdocia-collect` (api, portail) et `piecemaster`.
