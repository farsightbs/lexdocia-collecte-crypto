import type { EncryptedFile, RecipientPrivateKeys, RecipientPublicKeys } from './types.js';
/**
 * Chiffre un fichier pour les clés publiques d'un destinataire (spec §3.3, portail).
 * Retourne deux blobs distincts qui suivent le modèle de données (§4) :
 * `ciphertext` va en Object Storage (`storage_key`), `encapsulatedKey` en base
 * (`cle_fichier_encapsulee`).
 */
export declare function encryptFile(plaintext: Uint8Array, recipient: RecipientPublicKeys): Promise<EncryptedFile>;
/**
 * Déchiffre un fichier avec les clés privées du destinataire (spec §3.4, PieceMaster).
 * Toute altération (byte modifié, mauvaise clé, structure invalide) lève une erreur —
 * jamais de déchiffrement partiel silencieux.
 */
export declare function decryptFile(encrypted: EncryptedFile, recipient: RecipientPrivateKeys): Promise<Uint8Array>;
