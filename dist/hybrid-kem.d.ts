import type { RecipientPrivateKeys, RecipientPublicKeys } from './types.js';
export interface HybridEncapsulation {
    sharedSecret: Uint8Array;
    ephemeralX25519PublicKey: Uint8Array;
    mlkemCiphertext: Uint8Array;
}
/** Chiffrement (portail) : encapsule un secret partagé pour les clés publiques du destinataire. */
export declare function hybridEncapsulate(recipient: RecipientPublicKeys): Promise<HybridEncapsulation>;
/** Déchiffrement (PieceMaster) : reconstitue le secret partagé à partir des clés privées. */
export declare function hybridDecapsulate(recipient: RecipientPrivateKeys, ephemeralX25519PublicKey: Uint8Array, mlkemCiphertext: Uint8Array): Promise<Uint8Array>;
