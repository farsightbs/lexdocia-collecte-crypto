import { getSodiumSumo } from './sodium-sumo.js';
import { FORMAT_VERSION, XWING_PRIVATE_KEY_BYTES, XCHACHA20POLY1305_NONCE_BYTES, } from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
/** Contenu en clair : la graine X-Wing de 32 octets. */
const PLAINTEXT_LENGTH = XWING_PRIVATE_KEY_BYTES;
/**
 * OPSLIMIT/MEMLIMIT "sensitive" par défaut : cette clé protège le déchiffrement de tous les
 * documents d'un cabinet, et l'export/import de ce fichier est une opération rare et
 * consciente (pas un flux de login) — quelques secondes de calcul sont un coût acceptable
 * pour ce niveau d'enjeu. Paramétrable pour les tests, qui n'ont pas besoin de cette marge.
 */
async function defaultLimits() {
    const sodium = await getSodiumSumo();
    return {
        opslimit: sodium.crypto_pwhash_OPSLIMIT_SENSITIVE,
        memlimit: sodium.crypto_pwhash_MEMLIMIT_SENSITIVE,
    };
}
async function deriveKey(password, salt, limits) {
    const sodium = await getSodiumSumo();
    return sodium.crypto_pwhash(32, password, salt, limits.opslimit, limits.memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
}
/**
 * Chiffre les clés privées de l'avocat par mot de passe (spec §3.2.3). `limits` n'est à
 * fournir que dans les tests, pour éviter le coût Argon2id "sensitive" en boucle.
 */
export async function exportRecoveryFile(keys, password, limits) {
    const sodium = await getSodiumSumo();
    const resolvedLimits = limits ?? (await defaultLimits());
    if (keys.privateKey.length !== PLAINTEXT_LENGTH) {
        throw new InvalidEnvelopeError(`Clé privée X-Wing invalide : ${PLAINTEXT_LENGTH} octets attendus, ${keys.privateKey.length} reçus.`);
    }
    const plaintext = keys.privateKey.slice();
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const key = await deriveKey(password, salt, resolvedLimits);
    const nonce = sodium.randombytes_buf(XCHACHA20POLY1305_NONCE_BYTES);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key);
    sodium.memzero(plaintext);
    sodium.memzero(key);
    return {
        version: FORMAT_VERSION,
        kdf: {
            algo: 'argon2id',
            salt: sodium.to_base64(salt),
            opslimit: resolvedLimits.opslimit,
            memlimit: resolvedLimits.memlimit,
        },
        nonce: sodium.to_base64(nonce),
        ciphertext: sodium.to_base64(ciphertext),
    };
}
/**
 * Déchiffre un fichier de recovery avec le mot de passe de l'avocat. Toute altération
 * (mauvais mot de passe, structure invalide, données corrompues) lève une erreur — jamais
 * de déchiffrement partiel silencieux (même garantie que `decryptFile`).
 */
export async function importRecoveryFile(file, password) {
    const sodium = await getSodiumSumo();
    if (file.version !== FORMAT_VERSION) {
        throw new InvalidEnvelopeError('Version de format de recovery non supportée.');
    }
    if (file.kdf.algo !== 'argon2id') {
        throw new InvalidEnvelopeError('Algorithme de dérivation de clé non supporté.');
    }
    let salt;
    let nonce;
    let ciphertext;
    try {
        salt = sodium.from_base64(file.kdf.salt);
        nonce = sodium.from_base64(file.nonce);
        ciphertext = sodium.from_base64(file.ciphertext);
    }
    catch {
        throw new InvalidEnvelopeError('Fichier de recovery illisible : base64 invalide.');
    }
    if (salt.length !== sodium.crypto_pwhash_SALTBYTES) {
        throw new InvalidEnvelopeError('Fichier de recovery illisible : sel de taille invalide.');
    }
    if (nonce.length !== XCHACHA20POLY1305_NONCE_BYTES) {
        throw new InvalidEnvelopeError('Fichier de recovery illisible : nonce de taille invalide.');
    }
    // Les paramètres viennent du fichier : on les borne pour qu'un fichier forgé ne puisse pas demander
    // des gigaoctets de mémoire (limite « sensitive » = ce que `exportRecoveryFile` produit au maximum).
    const { opslimit, memlimit } = file.kdf;
    if (!Number.isInteger(opslimit) ||
        !Number.isInteger(memlimit) ||
        opslimit < 1 ||
        memlimit < 8192 ||
        opslimit > sodium.crypto_pwhash_OPSLIMIT_SENSITIVE ||
        memlimit > sodium.crypto_pwhash_MEMLIMIT_SENSITIVE) {
        throw new InvalidEnvelopeError('Fichier de recovery illisible : paramètres Argon2id hors limites.');
    }
    const key = await deriveKey(password, salt, { opslimit, memlimit });
    let plaintext;
    try {
        plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key);
    }
    catch {
        throw new DecryptionError('Mot de passe incorrect ou fichier de recovery corrompu.');
    }
    finally {
        sodium.memzero(key);
    }
    if (plaintext.length !== PLAINTEXT_LENGTH) {
        sodium.memzero(plaintext);
        throw new InvalidEnvelopeError(`Taille de contenu déchiffré invalide : attendu ${PLAINTEXT_LENGTH} octets, reçu ${plaintext.length}.`);
    }
    const privateKey = plaintext.slice();
    sodium.memzero(plaintext);
    return { privateKey };
}
//# sourceMappingURL=recovery.js.map