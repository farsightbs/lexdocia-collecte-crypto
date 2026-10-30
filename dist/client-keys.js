import { getSodium } from './sodium.js';
import { FORMAT_VERSION, XWING_PRIVATE_KEY_BYTES, XCHACHA20POLY1305_NONCE_BYTES, XCHACHA20POLY1305_TAG_BYTES, } from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
import { decryptFile, encryptFile } from './envelope.js';
/**
 * Espace sécurisé du client (spec §3.10) : le client est destinataire des envois de l'avocat. Sa paire de clés
 * (générée par `generateAvocatKeyPair`, même X-Wing) est protégée par un secret de 32 octets issu de sa
 * passkey (extension WebAuthn PRF) — jamais par un mot de passe.
 */
const SECRET_BYTES = 32;
/** Contexte `crypto_kdf` (8 caractères exactement) : sépare cet usage de tout autre dérivé du même secret. */
const WRAP_KDF_CONTEXT = 'lxdcclnt';
const WRAP_KDF_SUBKEY_ID = 1;
const PLAINTEXT_LENGTH = XWING_PRIVATE_KEY_BYTES;
const SEALED_HEADER_LENGTH = 1 + XCHACHA20POLY1305_NONCE_BYTES;
export const SEALED_PRIVATE_KEYS_LENGTH = SEALED_HEADER_LENGTH + PLAINTEXT_LENGTH + XCHACHA20POLY1305_TAG_BYTES;
async function wrapKey(secret) {
    if (secret.length !== SECRET_BYTES) {
        throw new InvalidEnvelopeError(`Secret de passkey invalide : ${SECRET_BYTES} octets attendus, ${secret.length} reçus.`);
    }
    const sodium = await getSodium();
    return sodium.crypto_kdf_derive_from_key(32, WRAP_KDF_SUBKEY_ID, WRAP_KDF_CONTEXT, secret);
}
/**
 * Chiffre les clés privées du client avec le secret issu de sa passkey. Format :
 * `[version(1)] [nonce(24)] [graine X-Wing(32) + tag(16)]`. Seul ce blob est conservé par le serveur.
 */
export async function sealPrivateKeys(keys, secret) {
    const sodium = await getSodium();
    const key = await wrapKey(secret);
    if (keys.privateKey.length !== PLAINTEXT_LENGTH) {
        throw new InvalidEnvelopeError(`Clé privée X-Wing invalide : ${PLAINTEXT_LENGTH} octets attendus, ${keys.privateKey.length} reçus.`);
    }
    const plaintext = keys.privateKey.slice();
    const nonce = sodium.randombytes_buf(XCHACHA20POLY1305_NONCE_BYTES);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key);
    sodium.memzero(plaintext);
    sodium.memzero(key);
    const sealed = new Uint8Array(SEALED_HEADER_LENGTH + ciphertext.length);
    sealed[0] = FORMAT_VERSION;
    sealed.set(nonce, 1);
    sealed.set(ciphertext, SEALED_HEADER_LENGTH);
    return sealed;
}
/** Inverse de `sealPrivateKeys`. Toute altération ou mauvais secret lève une erreur, jamais de résultat partiel. */
export async function openPrivateKeys(sealed, secret) {
    const sodium = await getSodium();
    if (sealed.length !== SEALED_PRIVATE_KEYS_LENGTH) {
        throw new InvalidEnvelopeError(`Clés privées chiffrées de taille invalide : ${SEALED_PRIVATE_KEYS_LENGTH} octets attendus, ${sealed.length} reçus.`);
    }
    if (sealed[0] !== FORMAT_VERSION) {
        throw new InvalidEnvelopeError('Version de format des clés chiffrées non supportée.');
    }
    const key = await wrapKey(secret);
    let plaintext;
    try {
        plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, sealed.subarray(SEALED_HEADER_LENGTH), null, sealed.subarray(1, SEALED_HEADER_LENGTH), key);
    }
    catch {
        throw new DecryptionError('Passkey incorrecte ou clés chiffrées corrompues.');
    }
    finally {
        sodium.memzero(key);
    }
    const keys = { privateKey: plaintext.slice() };
    sodium.memzero(plaintext);
    return keys;
}
/**
 * Empreinte courte de la clé publique d'un destinataire (BLAKE2b-128 de la clé X-Wing, 8 groupes de
 * 4 caractères hexadécimaux) : affichée au client à l'activation et à l'avocat, qui peut la faire confirmer par
 * téléphone — détecte la substitution d'une clé publique par le serveur.
 */
export async function fingerprintPublicKeys(keys) {
    const sodium = await getSodium();
    const digest = sodium.crypto_generichash(16, keys.publicKey, null);
    const hex = sodium.to_hex(digest);
    return (hex.match(/.{4}/g) ?? []).join(' ');
}
/** Chiffre un petit objet JSON (métadonnées : nom du fichier, libellé…) pour un destinataire. */
export async function encryptJson(value, recipient) {
    return encryptFile(new TextEncoder().encode(JSON.stringify(value)), recipient);
}
export async function decryptJson(encrypted, recipient) {
    const plaintext = await decryptFile(encrypted, recipient);
    return JSON.parse(new TextDecoder().decode(plaintext));
}
//# sourceMappingURL=client-keys.js.map