export { generateAvocatKeyPair } from './keys.js';
export { encryptFile, decryptFile } from './envelope.js';
export { exportRecoveryFile, importRecoveryFile } from './recovery.js';
export { sealPrivateKeys, openPrivateKeys, fingerprintPublicKeys, encryptJson, decryptJson, SEALED_PRIVATE_KEYS_LENGTH, } from './client-keys.js';
export { CollecteCryptoError, DecryptionError, InvalidEnvelopeError } from './errors.js';
export type { AvocatKeyPair, KeyPairBytes, EncryptedFile, RecipientPublicKeys, RecipientPrivateKeys, } from './types.js';
export type { RecoveryFile } from './recovery.js';
export { ENCAPSULATED_KEY_LENGTH, XWING_PUBLIC_KEY_BYTES, XWING_PRIVATE_KEY_BYTES, XWING_CIPHERTEXT_BYTES, } from './constants.js';
