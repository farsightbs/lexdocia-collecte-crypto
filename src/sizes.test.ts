import { describe, expect, it } from 'vitest';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import {
  XWING_CIPHERTEXT_BYTES,
  XWING_PRIVATE_KEY_BYTES,
  XWING_PUBLIC_KEY_BYTES,
  XWING_SHARED_SECRET_BYTES,
} from './constants.js';

/**
 * Les tailles X-Wing sont codées en dur dans constants.ts (ce sont des constantes de
 * draft-connolly-cfrg-xwing-kem, pas des détails d'implémentation). Ce test garde-fou vérifie
 * qu'elles restent alignées avec la librairie réellement installée — s'il échoue après une mise
 * à jour de @noble/post-quantum, quelque chose de plus grave qu'un simple changement de taille
 * se passe.
 */
describe('tailles X-Wing', () => {
  it('correspondent aux constantes déclarées', () => {
    expect(xwing.lengths.publicKey).toBe(XWING_PUBLIC_KEY_BYTES);
    expect(xwing.lengths.secretKey).toBe(XWING_PRIVATE_KEY_BYTES);
    expect(xwing.lengths.cipherText).toBe(XWING_CIPHERTEXT_BYTES);
  });

  it('produisent des clés et un encapsulé de la bonne taille', () => {
    const { publicKey, secretKey } = xwing.keygen();
    expect(publicKey.length).toBe(XWING_PUBLIC_KEY_BYTES);
    expect(secretKey.length).toBe(XWING_PRIVATE_KEY_BYTES);

    const { cipherText, sharedSecret } = xwing.encapsulate(publicKey);
    expect(cipherText.length).toBe(XWING_CIPHERTEXT_BYTES);
    expect(sharedSecret.length).toBe(XWING_SHARED_SECRET_BYTES);
  });
});
