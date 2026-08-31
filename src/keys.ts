import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { getSodium } from './sodium.js';
import type { AvocatKeyPair } from './types.js';

/**
 * Génère une paire de clés X25519 + une paire ML-KEM-768 (spec §3.2.1). Les clés privées
 * ne doivent jamais quitter le poste — c'est à l'appelant (PieceMaster) de les persister
 * localement et de gérer l'export chiffré de recovery (§3.2.3), hors scope de ce package.
 */
export async function generateAvocatKeyPair(): Promise<AvocatKeyPair> {
  const sodium = await getSodium();
  const x25519 = sodium.crypto_box_keypair();
  const mlkem = ml_kem768.keygen();

  return {
    x25519: { publicKey: x25519.publicKey, privateKey: x25519.privateKey },
    mlkem: { publicKey: mlkem.publicKey, privateKey: mlkem.secretKey },
  };
}
