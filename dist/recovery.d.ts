import type { RecipientPrivateKeys } from './types.js';
/** Fichier de recovery des clés privées de l'avocat (spec §3.2.3, §12.1) — exporté une fois
 * juste après la génération des clés, à sauvegarder par l'avocat hors du poste. */
export interface RecoveryFile {
    version: number;
    kdf: {
        algo: 'argon2id';
        /** base64, `crypto_pwhash_SALTBYTES` */
        salt: string;
        opslimit: number;
        memlimit: number;
    };
    /** base64, `XCHACHA20POLY1305_NONCE_BYTES` */
    nonce: string;
    /** base64 */
    ciphertext: string;
}
interface Argon2idLimits {
    opslimit: number;
    memlimit: number;
}
/**
 * Chiffre les clés privées de l'avocat par mot de passe (spec §3.2.3). `limits` n'est à
 * fournir que dans les tests, pour éviter le coût Argon2id "sensitive" en boucle.
 */
export declare function exportRecoveryFile(keys: RecipientPrivateKeys, password: string, limits?: Argon2idLimits): Promise<RecoveryFile>;
/**
 * Déchiffre un fichier de recovery avec le mot de passe de l'avocat. Toute altération
 * (mauvais mot de passe, structure invalide, données corrompues) lève une erreur — jamais
 * de déchiffrement partiel silencieux (même garantie que `decryptFile`).
 */
export declare function importRecoveryFile(file: RecoveryFile, password: string): Promise<RecipientPrivateKeys>;
export {};
