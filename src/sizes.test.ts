import { describe, expect, it } from 'vitest';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  MLKEM768_CIPHERTEXT_BYTES,
  MLKEM768_PUBLIC_KEY_BYTES,
  MLKEM768_SECRET_KEY_BYTES,
  MLKEM768_SHARED_SECRET_BYTES,
} from './constants.js';

/**
 * Les tailles ML-KEM-768 sont codées en dur dans constants.ts (ce sont des constantes
 * FIPS 203, pas des détails d'implémentation). Ce test garde-fou vérifie qu'elles restent
 * alignées avec la librairie réellement installée — s'il échoue après une mise à jour de
 * @noble/post-quantum, quelque chose de plus grave qu'un simple changement de taille se passe.
 */
describe('tailles ML-KEM-768', () => {
  it('correspondent aux constantes FIPS 203 déclarées', () => {
    expect(ml_kem768.lengths.publicKey).toBe(MLKEM768_PUBLIC_KEY_BYTES);
    expect(ml_kem768.lengths.secretKey).toBe(MLKEM768_SECRET_KEY_BYTES);
  });

  it('produisent des clés générées de la bonne taille', () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    expect(publicKey.length).toBe(MLKEM768_PUBLIC_KEY_BYTES);
    expect(secretKey.length).toBe(MLKEM768_SECRET_KEY_BYTES);

    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    expect(cipherText.length).toBe(MLKEM768_CIPHERTEXT_BYTES);
    expect(sharedSecret.length).toBe(MLKEM768_SHARED_SECRET_BYTES);
  });
});
