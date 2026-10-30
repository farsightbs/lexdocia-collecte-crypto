import { describe, expect, it } from 'vitest';
import { generateAvocatKeyPair } from './keys.js';
import { XWING_PRIVATE_KEY_BYTES, XWING_PUBLIC_KEY_BYTES } from './constants.js';

describe('generateAvocatKeyPair', () => {
  it('génère une paire X-Wing de la bonne taille', async () => {
    const keyPair = await generateAvocatKeyPair();

    expect(keyPair.publicKey.length).toBe(XWING_PUBLIC_KEY_BYTES);
    expect(keyPair.privateKey.length).toBe(XWING_PRIVATE_KEY_BYTES);
  });

  it('génère des paires distinctes à chaque appel', async () => {
    const a = await generateAvocatKeyPair();
    const b = await generateAvocatKeyPair();

    expect(a.privateKey).not.toEqual(b.privateKey);
    expect(a.publicKey).not.toEqual(b.publicKey);
  });
});
