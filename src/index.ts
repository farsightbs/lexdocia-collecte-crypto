export { generateAvocatKeyPair } from './keys.js';
export { encryptFile, decryptFile } from './envelope.js';
export { exportRecoveryFile, importRecoveryFile } from './recovery.js';
export { CollecteCryptoError, DecryptionError, InvalidEnvelopeError } from './errors.js';
export type {
  AvocatKeyPair,
  KeyPairBytes,
  EncryptedFile,
  RecipientPublicKeys,
  RecipientPrivateKeys,
} from './types.js';
export type { RecoveryFile } from './recovery.js';
export {
  ENCAPSULATED_KEY_LENGTH,
  MLKEM768_PUBLIC_KEY_BYTES,
  MLKEM768_SECRET_KEY_BYTES,
  X25519_PUBLIC_KEY_BYTES,
  X25519_PRIVATE_KEY_BYTES,
} from './constants.js';
