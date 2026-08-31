import { describe, expect, it } from 'vitest';
import { generateAvocatKeyPair } from './keys.js';
import {
  MLKEM768_PUBLIC_KEY_BYTES,
  MLKEM768_SECRET_KEY_BYTES,
  X25519_PRIVATE_KEY_BYTES,
  X25519_PUBLIC_KEY_BYTES,
} from './constants.js';

describe('generateAvocatKeyPair', () => {
  it('génère des clés X25519 et ML-KEM-768 de la bonne taille', async () => {
    const keyPair = await generateAvocatKeyPair();

    expect(keyPair.x25519.publicKey.length).toBe(X25519_PUBLIC_KEY_BYTES);
    expect(keyPair.x25519.privateKey.length).toBe(X25519_PRIVATE_KEY_BYTES);
    expect(keyPair.mlkem.publicKey.length).toBe(MLKEM768_PUBLIC_KEY_BYTES);
    expect(keyPair.mlkem.privateKey.length).toBe(MLKEM768_SECRET_KEY_BYTES);
  });

  it('génère des clés différentes à chaque appel', async () => {
    const a = await generateAvocatKeyPair();
    const b = await generateAvocatKeyPair();

    expect(a.x25519.privateKey).not.toEqual(b.x25519.privateKey);
    expect(a.mlkem.privateKey).not.toEqual(b.mlkem.privateKey);
  });
});
