export interface KeyPairBytes {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}
/**
 * Paire de clés X-Wing générée localement à l'activation du module Collecte (spec §3.2).
 * `publicKey` : 1216 octets ; `privateKey` : graine de 32 octets (jamais transmise).
 */
export type AvocatKeyPair = KeyPairBytes;
/** Clé publique du destinataire, telle que récupérée par le portail avant chiffrement. */
export interface RecipientPublicKeys {
    publicKey: Uint8Array;
}
/** Clé privée du destinataire, jamais transmise — utilisée localement dans PieceMaster. */
export interface RecipientPrivateKeys {
    privateKey: Uint8Array;
}
/**
 * Résultat du chiffrement d'un fichier (spec §3.3). Les deux champs sont stockés/transportés
 * séparément : `ciphertext` en Object Storage (`storage_key`), `encapsulatedKey` en base
 * (`cle_fichier_encapsulee`).
 */
export interface EncryptedFile {
    ciphertext: Uint8Array;
    encapsulatedKey: Uint8Array;
}
