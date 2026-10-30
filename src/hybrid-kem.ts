import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import {
  XWING_CIPHERTEXT_BYTES,
  XWING_PRIVATE_KEY_BYTES,
  XWING_PUBLIC_KEY_BYTES,
} from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';

/**
 * KEM hybride X-Wing (X25519 + ML-KEM-768), tel que spécifié par draft-connolly-cfrg-xwing-kem :
 * le combineur (SHA3-256 sur les deux secrets, le ciphertext X25519 et la clé publique X25519)
 * est celui de la librairie, testé contre les vecteurs du draft — rien n'est recomposé ici.
 */

export interface XWingEncapsulation {
  sharedSecret: Uint8Array;
  cipherText: Uint8Array;
}

/** Chiffrement (portail) : encapsule un secret partagé pour la clé publique du destinataire. */
export function xwingEncapsulate(publicKey: Uint8Array): XWingEncapsulation {
  if (publicKey.length !== XWING_PUBLIC_KEY_BYTES) {
    throw new InvalidEnvelopeError(
      `Clé publique X-Wing invalide : ${XWING_PUBLIC_KEY_BYTES} octets attendus, ${publicKey.length} reçus.`,
    );
  }
  const { cipherText, sharedSecret } = xwing.encapsulate(publicKey);
  return { sharedSecret, cipherText };
}

/** Déchiffrement (PieceMaster) : reconstitue le secret partagé à partir de la clé privée. */
export function xwingDecapsulate(cipherText: Uint8Array, privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== XWING_PRIVATE_KEY_BYTES) {
    throw new InvalidEnvelopeError(
      `Clé privée X-Wing invalide : ${XWING_PRIVATE_KEY_BYTES} octets attendus, ${privateKey.length} reçus.`,
    );
  }
  if (cipherText.length !== XWING_CIPHERTEXT_BYTES) {
    throw new DecryptionError('Ciphertext X-Wing de taille invalide.');
  }
  try {
    return xwing.decapsulate(cipherText, privateKey);
  } catch {
    throw new DecryptionError('Décapsulation X-Wing invalide : ciphertext corrompu ou mauvaise clé.');
  }
}
