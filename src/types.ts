export interface KeyPairBytes {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Paire de clés générée localement à l'activation du module Collecte (spec §3.2). */
export interface AvocatKeyPair {
  x25519: KeyPairBytes;
  mlkem: KeyPairBytes;
}

/** Clés publiques de l'avocat, telles que récupérées par le portail avant chiffrement. */
export interface RecipientPublicKeys {
  x25519PublicKey: Uint8Array;
  mlkemPublicKey: Uint8Array;
}

/** Clés privées de l'avocat, jamais transmises — utilisées localement dans PieceMaster. */
export interface RecipientPrivateKeys {
  x25519PrivateKey: Uint8Array;
  mlkemPrivateKey: Uint8Array;
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
