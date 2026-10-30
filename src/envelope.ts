import { getSodium } from './sodium.js';
import { xwingDecapsulate, xwingEncapsulate } from './hybrid-kem.js';
import {
  ENCAPSULATED_KEY_LENGTH,
  FILE_KEY_BYTES,
  FORMAT_VERSION,
  XCHACHA20POLY1305_NONCE_BYTES,
  XCHACHA20POLY1305_TAG_BYTES,
  XWING_CIPHERTEXT_BYTES,
} from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
import type { EncryptedFile, RecipientPrivateKeys, RecipientPublicKeys } from './types.js';

const CIPHERTEXT_HEADER_LENGTH = 1 + XCHACHA20POLY1305_NONCE_BYTES;
const KEM_CIPHERTEXT_END = 1 + XWING_CIPHERTEXT_BYTES;

/** Données authentifiées de l'enveloppe du fichier : l'octet de version. */
function fileAad(): Uint8Array {
  return Uint8Array.of(FORMAT_VERSION);
}

/**
 * Données authentifiées de l'enveloppe de la clé de fichier : version ‖ ciphertext X-Wing.
 * Lie la clé enveloppée au ciphertext KEM qui l'a produite (un ciphertext échangé ou altéré
 * fait échouer l'authentification, en plus de produire un autre secret).
 */
function keyAad(encapsulatedKey: Uint8Array): Uint8Array {
  return encapsulatedKey.slice(0, KEM_CIPHERTEXT_END);
}

/**
 * Chiffre un fichier pour la clé publique d'un destinataire (spec §3.3, portail).
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
    fileAad(),
    null,
    fileNonce,
    fileKey,
  );

  const ciphertext = new Uint8Array(CIPHERTEXT_HEADER_LENGTH + fileCiphertext.length);
  ciphertext[0] = FORMAT_VERSION;
  ciphertext.set(fileNonce, 1);
  ciphertext.set(fileCiphertext, CIPHERTEXT_HEADER_LENGTH);

  const { sharedSecret, cipherText: kemCiphertext } = xwingEncapsulate(recipient.publicKey);

  const encapsulatedKey = new Uint8Array(ENCAPSULATED_KEY_LENGTH);
  encapsulatedKey[0] = FORMAT_VERSION;
  encapsulatedKey.set(kemCiphertext, 1);

  const keyNonce = sodium.randombytes_buf(XCHACHA20POLY1305_NONCE_BYTES);
  const wrappedFileKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    fileKey,
    keyAad(encapsulatedKey),
    null,
    keyNonce,
    sharedSecret,
  );
  sodium.memzero(fileKey);
  sodium.memzero(sharedSecret);

  encapsulatedKey.set(keyNonce, KEM_CIPHERTEXT_END);
  encapsulatedKey.set(wrappedFileKey, KEM_CIPHERTEXT_END + XCHACHA20POLY1305_NONCE_BYTES);

  return { ciphertext, encapsulatedKey };
}

/**
 * Déchiffre un fichier avec la clé privée du destinataire (spec §3.4, PieceMaster).
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

  const kemCiphertext = encapsulatedKey.subarray(1, KEM_CIPHERTEXT_END);
  const keyNonce = encapsulatedKey.subarray(
    KEM_CIPHERTEXT_END,
    KEM_CIPHERTEXT_END + XCHACHA20POLY1305_NONCE_BYTES,
  );
  const wrappedFileKey = encapsulatedKey.subarray(
    KEM_CIPHERTEXT_END + XCHACHA20POLY1305_NONCE_BYTES,
  );

  const sharedSecret = xwingDecapsulate(kemCiphertext, recipient.privateKey);

  let fileKey: Uint8Array;
  try {
    fileKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      wrappedFileKey,
      keyAad(encapsulatedKey),
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
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fileCiphertext,
      fileAad(),
      fileNonce,
      fileKey,
    );
  } catch {
    throw new DecryptionError('Impossible de déchiffrer le contenu du fichier.');
  } finally {
    sodium.memzero(fileKey);
  }
}
