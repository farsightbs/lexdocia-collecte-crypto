/**
 * Tailles fixes X-Wing (draft-connolly-cfrg-xwing-kem : ML-KEM-768 + X25519).
 * Codées en dur plutôt que lues dynamiquement sur `ml_kem768_x25519.lengths` : ce sont des
 * constantes de la spécification, pas des détails d'implémentation. Un test (`sizes.test.ts`)
 * vérifie qu'elles restent alignées avec la librairie installée.
 *
 * La clé privée est la graine de 32 octets dont X-Wing dérive (SHAKE256) les clés ML-KEM-768
 * et X25519. La clé publique est `pk_ML-KEM-768 (1184) ‖ pk_X25519 (32)`.
 */
export const XWING_PUBLIC_KEY_BYTES = 1216;
export const XWING_PRIVATE_KEY_BYTES = 32;
export const XWING_CIPHERTEXT_BYTES = 1120;
export const XWING_SHARED_SECRET_BYTES = 32;

/**
 * Clé de fichier symétrique et secret partagé X-Wing. XChaCha20-Poly1305 plutôt
 * qu'AES-256-GCM (les deux sont autorisés par la spec §3.1) : disponible sans détection
 * de support matériel AES-NI dans libsodium, et nonce 24 octets tolérant un tirage
 * aléatoire par message sans registre de compteur à synchroniser.
 */
export const FILE_KEY_BYTES = 32;
export const XCHACHA20POLY1305_NONCE_BYTES = 24;
export const XCHACHA20POLY1305_TAG_BYTES = 16;

/**
 * Version 2 : passage de l'hybride maison (X25519 + ML-KEM-768 combinés par BLAKE2b) à X-Wing.
 * Aucune lecture du format v1 : les données v1 ont été remises à zéro lors de la migration.
 */
export const FORMAT_VERSION = 2;

/**
 * Layout binaire de la clé de fichier encapsulée (§3.3), colonne `cle_fichier_encapsulee` :
 * [version(1)] [ciphertext X-Wing(1120)] [nonce clé enveloppée(24)] [clé de fichier chiffrée + tag(32+16)]
 */
export const ENCAPSULATED_KEY_LENGTH =
  1 +
  XWING_CIPHERTEXT_BYTES +
  XCHACHA20POLY1305_NONCE_BYTES +
  (FILE_KEY_BYTES + XCHACHA20POLY1305_TAG_BYTES);
