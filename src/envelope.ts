import { getSodium } from './sodium.js';
import { hybridDecapsulate, hybridEncapsulate } from './hybrid-kem.js';
import {
  ENCAPSULATED_KEY_LENGTH,
  FILE_KEY_BYTES,
  FORMAT_VERSION,
  MLKEM768_CIPHERTEXT_BYTES,
  X25519_PUBLIC_KEY_BYTES,
  XCHACHA20POLY1305_NONCE_BYTES,
  XCHACHA20POLY1305_TAG_BYTES,
} from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
import type { EncryptedFile, RecipientPrivateKeys, RecipientPublicKeys } from './types.js';

const CIPHERTEXT_HEADER_LENGTH = 1 + XCHACHA20POLY1305_NONCE_BYTES;

/**
 * Chiffre un fichier pour les clés publiques d'un destinataire (spec §3.3, portail).
 * Retourne deux blobs distincts qui suivent le modèle de données (§4) :
 * `ciphertext` va en Object Storage (`storage_key`), `encapsulatedKey` en base
 * (`cle_fichier_encapsulee`).
 */
export async function encryptFile(
  plaintext: Uint8Array,
  recipient: RecipientPublicKeys,
): Promise<EncryptedFile> {
  const sodium = await getSodium();
  const fileKey = sodium.randombytes_buf(FILE_KEY_BYTES);
  const fileNonce = sodium.randombytes_buf(XCHACHA20POLY1305_NONCE_BYTES);
  const fileCiphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null,
    null,
    fileNonce,
    fileKey,
  );

  const ciphertext = new Uint8Array(CIPHERTEXT_HEADER_LENGTH + fileCiphertext.length);
  ciphertext[0] = FORMAT_VERSION;
  ciphertext.set(fileNonce, 1);
  ciphertext.set(fileCiphertext, CIPHERTEXT_HEADER_LENGTH);

  const { sharedSecret, ephemeralX25519PublicKey, mlkemCiphertext } =
    await hybridEncapsulate(recipient);
  const keyNonce = sodium.randombytes_buf(XCHACHA20POLY1305_NONCE_BYTES);
  const wrappedFileKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    fileKey,
    null,
    null,
    keyNonce,
    sharedSecret,
  );
  sodium.memzero(fileKey);
  sodium.memzero(sharedSecret);

  let offset = 0;
  const encapsulatedKey = new Uint8Array(ENCAPSULATED_KEY_LENGTH);
  encapsulatedKey[offset] = FORMAT_VERSION;
  offset += 1;
  encapsulatedKey.set(ephemeralX25519PublicKey, offset);
  offset += X25519_PUBLIC_KEY_BYTES;
  encapsulatedKey.set(mlkemCiphertext, offset);
  offset += MLKEM768_CIPHERTEXT_BYTES;
  encapsulatedKey.set(keyNonce, offset);
  offset += XCHACHA20POLY1305_NONCE_BYTES;
  encapsulatedKey.set(wrappedFileKey, offset);

  return { ciphertext, encapsulatedKey };
}

/**
 * Déchiffre un fichier avec les clés privées du destinataire (spec §3.4, PieceMaster).
 * Toute altération (byte modifié, mauvaise clé, structure invalide) lève une erreur —
 * jamais de déchiffrement partiel silencieux.
 */
export async function decryptFile(
  encrypted: EncryptedFile,
  recipient: RecipientPrivateKeys,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  const { ciphertext, encapsulatedKey } = encrypted;

  if (encapsulatedKey.length !== ENCAPSULATED_KEY_LENGTH) {
    throw new InvalidEnvelopeError(
      `Taille de clé encapsulée invalide : attendu ${ENCAPSULATED_KEY_LENGTH} octets, reçu ${encapsulatedKey.length}.`,
    );
  }
  if (ciphertext.length < CIPHERTEXT_HEADER_LENGTH + XCHACHA20POLY1305_TAG_BYTES) {
    throw new InvalidEnvelopeError('Blob chiffré trop court pour être valide.');
  }
  if (encapsulatedKey[0] !== FORMAT_VERSION || ciphertext[0] !== FORMAT_VERSION) {
    throw new InvalidEnvelopeError('Version de format de chiffrement non supportée.');
  }

  let offset = 1;
  const ephemeralX25519PublicKey = encapsulatedKey.subarray(
    offset,
    offset + X25519_PUBLIC_KEY_BYTES,
  );
  offset += X25519_PUBLIC_KEY_BYTES;
  const mlkemCiphertext = encapsulatedKey.subarray(offset, offset + MLKEM768_CIPHERTEXT_BYTES);
  offset += MLKEM768_CIPHERTEXT_BYTES;
  const keyNonce = encapsulatedKey.subarray(offset, offset + XCHACHA20POLY1305_NONCE_BYTES);
  offset += XCHACHA20POLY1305_NONCE_BYTES;
  const wrappedFileKey = encapsulatedKey.subarray(offset);

  const sharedSecret = await hybridDecapsulate(
    recipient,
    ephemeralX25519PublicKey,
    mlkemCiphertext,
  );

  let fileKey: Uint8Array;
  try {
    fileKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      wrappedFileKey,
      null,
      keyNonce,
      sharedSecret,
    );
  } catch {
    throw new DecryptionError('Impossible de déchiffrer la clé de fichier encapsulée.');
  } finally {
    sodium.memzero(sharedSecret);
  }

  const fileNonce = ciphertext.subarray(1, CIPHERTEXT_HEADER_LENGTH);
  const fileCiphertext = ciphertext.subarray(CIPHERTEXT_HEADER_LENGTH);

  try {
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fileCiphertext,
      null,
      fileNonce,
      fileKey,
    );
    return plaintext;
  } catch {
    throw new DecryptionError('Impossible de déchiffrer le contenu du fichier.');
  } finally {
    sodium.memzero(fileKey);
  }
}
