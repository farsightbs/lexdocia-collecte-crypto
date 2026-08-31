import type { AvocatKeyPair } from './types.js';
/**
 * Génère une paire de clés X25519 + une paire ML-KEM-768 (spec §3.2.1). Les clés privées
 * ne doivent jamais quitter le poste — c'est à l'appelant (PieceMaster) de les persister
 * localement et de gérer l'export chiffré de recovery (§3.2.3), hors scope de ce package.
 */
export declare function generateAvocatKeyPair(): Promise<AvocatKeyPair>;
