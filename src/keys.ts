import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import type { AvocatKeyPair } from './types.js';

/**
 * Génère une paire de clés X-Wing (spec §3.2.1). La clé privée (graine de 32 octets) ne doit
 * jamais quitter le poste — c'est à l'appelant (PieceMaster) de la persister localement et de
 * gérer l'export chiffré de recovery (§3.2.3), hors scope de ce package.
 */
export async function generateAvocatKeyPair(): Promise<AvocatKeyPair> {
  const { publicKey, secretKey } = xwing.keygen();
  return { publicKey, privateKey: secretKey };
}
