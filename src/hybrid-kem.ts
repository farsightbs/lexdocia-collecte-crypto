import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { getSodium } from './sodium.js';
import { HYBRID_KDF_CONTEXT, X25519_SHARED_SECRET_BYTES } from './constants.js';
import type { RecipientPrivateKeys, RecipientPublicKeys } from './types.js';
import { DecryptionError } from './errors.js';

/**
 * Combine les deux secrets partagés (classique + post-quantique) en une seule clé
 * symétrique via BLAKE2b (concatenation KDF, cf. NIST SP 800-56C rev2). La sécurité du
 * résultat repose sur celle du plus fort des deux secrets d'entrée : si l'un des deux
 * algorithmes est cassé, l'autre continue de protéger le secret combiné.
 */
async function combineSharedSecrets(
  x25519Shared: Uint8Array,
  mlkemShared: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  const combined = new Uint8Array(x25519Shared.length + mlkemShared.length);
  combined.set(x25519Shared, 0);
  combined.set(mlkemShared, x25519Shared.length);
  const kek = sodium.crypto_generichash(32, combined, HYBRID_KDF_CONTEXT);
  sodium.memzero(combined);
  return kek;
}

export interface HybridEncapsulation {
  sharedSecret: Uint8Array;
  ephemeralX25519PublicKey: Uint8Array;
  mlkemCiphertext: Uint8Array;
}

/** Chiffrement (portail) : encapsule un secret partagé pour les clés publiques du destinataire. */
export async function hybridEncapsulate(
  recipient: RecipientPublicKeys,
): Promise<HybridEncapsulation> {
  const sodium = await getSodium();
  const ephemeral = sodium.crypto_box_keypair();
  const x25519Shared = sodium.crypto_scalarmult(ephemeral.privateKey, recipient.x25519PublicKey);
  const { cipherText: mlkemCiphertext, sharedSecret: mlkemShared } = ml_kem768.encapsulate(
    recipient.mlkemPublicKey,
  );

  const sharedSecret = await combineSharedSecrets(x25519Shared, mlkemShared);
  sodium.memzero(ephemeral.privateKey);
  sodium.memzero(x25519Shared);
  sodium.memzero(mlkemShared);

  return { sharedSecret, ephemeralX25519PublicKey: ephemeral.publicKey, mlkemCiphertext };
}

/** Déchiffrement (PieceMaster) : reconstitue le secret partagé à partir des clés privées. */
export async function hybridDecapsulate(
  recipient: RecipientPrivateKeys,
  ephemeralX25519PublicKey: Uint8Array,
  mlkemCiphertext: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  if (ephemeralX25519PublicKey.length !== X25519_SHARED_SECRET_BYTES) {
    throw new DecryptionError('Clé publique X25519 éphémère de taille invalide.');
  }

  const x25519Shared = sodium.crypto_scalarmult(
    recipient.x25519PrivateKey,
    ephemeralX25519PublicKey,
  );

  let mlkemShared: Uint8Array;
  try {
    mlkemShared = ml_kem768.decapsulate(mlkemCiphertext, recipient.mlkemPrivateKey);
  } catch {
    sodium.memzero(x25519Shared);
    throw new DecryptionError(
      'Décapsulation ML-KEM invalide : ciphertext corrompu ou mauvaise clé.',
    );
  }

  const sharedSecret = await combineSharedSecrets(x25519Shared, mlkemShared);
  sodium.memzero(x25519Shared);
  sodium.memzero(mlkemShared);
  return sharedSecret;
}
