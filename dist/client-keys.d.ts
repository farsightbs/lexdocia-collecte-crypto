import type { EncryptedFile, RecipientPrivateKeys, RecipientPublicKeys } from './types.js';
export declare const SEALED_PRIVATE_KEYS_LENGTH: number;
/**
 * Chiffre les clés privées du client avec le secret issu de sa passkey. Format :
 * `[version(1)] [nonce(24)] [x25519 ‖ ml-kem + tag(16)]`. Seul ce blob est conservé par le serveur.
 */
export declare function sealPrivateKeys(keys: RecipientPrivateKeys, secret: Uint8Array): Promise<Uint8Array>;
/** Inverse de `sealPrivateKeys`. Toute altération ou mauvais secret lève une erreur, jamais de résultat partiel. */
export declare function openPrivateKeys(sealed: Uint8Array, secret: Uint8Array): Promise<RecipientPrivateKeys>;
/**
 * Empreinte courte des clés publiques d'un destinataire (BLAKE2b-128 des deux clés, 8 groupes de
 * 4 caractères hexadécimaux) : affichée au client à l'activation et à l'avocat, qui peut la faire confirmer par
 * téléphone — détecte la substitution d'une clé publique par le serveur.
 */
export declare function fingerprintPublicKeys(keys: RecipientPublicKeys): Promise<string>;
/** Chiffre un petit objet JSON (métadonnées : nom du fichier, libellé…) pour un destinataire. */
export declare function encryptJson(value: unknown, recipient: RecipientPublicKeys): Promise<EncryptedFile>;
export declare function decryptJson<T = unknown>(encrypted: EncryptedFile, recipient: RecipientPrivateKeys): Promise<T>;
