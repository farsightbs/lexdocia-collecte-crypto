export declare class CollecteCryptoError extends Error {
}
export declare class DecryptionError extends CollecteCryptoError {
    constructor(message?: string);
}
export declare class InvalidEnvelopeError extends CollecteCryptoError {
    constructor(message: string);
}
