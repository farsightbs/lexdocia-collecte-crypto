import { getSodiumSumo } from './sodium-sumo.js';
import { FORMAT_VERSION, MLKEM768_SECRET_KEY_BYTES, X25519_PRIVATE_KEY_BYTES, XCHACHA20POLY1305_NONCE_BYTES, } from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
/** Champs en clair, dans le même ordre que dans le fichier de recovery. */
const PLAINTEXT_LENGTH = X25519_PRIVATE_KEY_BYTES + MLKEM768_SECRET_KEY_BYTES;
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
    const plaintext = new Uint8Array(PLAINTEXT_LENGTH);
    plaintext.set(keys.x25519PrivateKey, 0);
    plaintext.set(keys.mlkemPrivateKey, X25519_PRIVATE_KEY_BYTES);
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
    const salt = sodium.from_base64(file.kdf.salt);
    const nonce = sodium.from_base64(file.nonce);
    const ciphertext = sodium.from_base64(file.ciphertext);
    const key = await deriveKey(password, salt, {
        opslimit: file.kdf.opslimit,
        memlimit: file.kdf.memlimit,
    });
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
    const x25519PrivateKey = plaintext.slice(0, X25519_PRIVATE_KEY_BYTES);
    const mlkemPrivateKey = plaintext.slice(X25519_PRIVATE_KEY_BYTES);
    sodium.memzero(plaintext);
    return { x25519PrivateKey, mlkemPrivateKey };
}
//# sourceMappingURL=recovery.js.map