export class CollecteCryptoError extends Error {
}
export class DecryptionError extends CollecteCryptoError {
    constructor(message = 'Échec du déchiffrement : clé incorrecte ou données corrompues/altérées.') {
        super(message);
        this.name = 'DecryptionError';
    }
}
export class InvalidEnvelopeError extends CollecteCryptoError {
    constructor(message) {
        super(message);
        this.name = 'InvalidEnvelopeError';
    }
}
//# sourceMappingURL=errors.js.map