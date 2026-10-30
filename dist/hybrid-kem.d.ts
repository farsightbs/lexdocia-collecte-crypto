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
export declare function xwingEncapsulate(publicKey: Uint8Array): XWingEncapsulation;
/** Déchiffrement (PieceMaster) : reconstitue le secret partagé à partir de la clé privée. */
export declare function xwingDecapsulate(cipherText: Uint8Array, privateKey: Uint8Array): Uint8Array;
