/**
 * Tailles fixes ML-KEM-768 (FIPS 203, Table 3 : 1184/2400/1088/32).
 * Codées en dur plutôt que lues dynamiquement sur `ml_kem768.lengths` : ce sont des
 * constantes du standard, pas des détails d'implémentation. Un test (`sizes.test.ts`)
 * vérifie qu'elles restent alignées avec la librairie installée.
 */
export declare const MLKEM768_PUBLIC_KEY_BYTES = 1184;
export declare const MLKEM768_SECRET_KEY_BYTES = 2400;
export declare const MLKEM768_CIPHERTEXT_BYTES = 1088;
export declare const MLKEM768_SHARED_SECRET_BYTES = 32;
export declare const X25519_PUBLIC_KEY_BYTES = 32;
export declare const X25519_PRIVATE_KEY_BYTES = 32;
export declare const X25519_SHARED_SECRET_BYTES = 32;
/**
 * Clé de fichier symétrique et secret combiné hybride. XChaCha20-Poly1305 plutôt
 * qu'AES-256-GCM (les deux sont autorisés par la spec §3.1) : disponible sans détection
 * de support matériel AES-NI dans libsodium, et nonce 24 octets tolérant un tirage
 * aléatoire par message sans registre de compteur à synchroniser.
 */
export declare const FILE_KEY_BYTES = 32;
export declare const XCHACHA20POLY1305_NONCE_BYTES = 24;
export declare const XCHACHA20POLY1305_TAG_BYTES = 16;
/** Contexte de séparation de domaine pour le KDF combinant les deux secrets partagés. */
export declare const HYBRID_KDF_CONTEXT: Uint8Array<ArrayBuffer>;
export declare const FORMAT_VERSION = 1;
/**
 * Layout binaire de la clé de fichier encapsulée (§3.3), colonne `cle_fichier_encapsulee` :
 * [version(1)] [x25519 ephemeral pubkey(32)] [ml-kem-768 ciphertext(1088)]
 * [nonce clé enveloppée(24)] [clé de fichier chiffrée + tag(32+16)]
 */
export declare const ENCAPSULATED_KEY_LENGTH: number;
