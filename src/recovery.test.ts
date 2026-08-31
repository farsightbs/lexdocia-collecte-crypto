import { describe, expect, it } from 'vitest';
import { generateAvocatKeyPair } from './keys.js';
import { exportRecoveryFile, importRecoveryFile, type RecoveryFile } from './recovery.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
import type { AvocatKeyPair, RecipientPrivateKeys } from './types.js';

function toPrivateKeys(keyPair: AvocatKeyPair): RecipientPrivateKeys {
  return {
    x25519PrivateKey: keyPair.x25519.privateKey,
    mlkemPrivateKey: keyPair.mlkem.privateKey,
  };
}

/** OPSLIMIT/MEMLIMIT minimaux valides pour libsodium — évite le coût "sensitive" en tests. */
const FAST_LIMITS = { opslimit: 1, memlimit: 8192 };

describe('exportRecoveryFile / importRecoveryFile', () => {
  it('fait un aller-retour fidèle sur les clés privées avec le bon mot de passe', async () => {
    const avocat = await generateAvocatKeyPair();
    const keys = toPrivateKeys(avocat);

    const file = await exportRecoveryFile(keys, 'mot-de-passe-avocat', FAST_LIMITS);
    const restored = await importRecoveryFile(file, 'mot-de-passe-avocat');

    expect(restored.x25519PrivateKey).toEqual(keys.x25519PrivateKey);
    expect(restored.mlkemPrivateKey).toEqual(keys.mlkemPrivateKey);
  });

  it('rejette un mauvais mot de passe', async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'bon-mot-de-passe', FAST_LIMITS);

    await expect(importRecoveryFile(file, 'mauvais-mot-de-passe')).rejects.toThrow(
      DecryptionError,
    );
  });

  it('rejette un fichier dont le ciphertext a été altéré', async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    const corrompu = { ...file, ciphertext: file.ciphertext.slice(0, -4) + 'AAAA' };

    await expect(importRecoveryFile(corrompu, 'mot-de-passe')).rejects.toThrow(DecryptionError);
  });

  it('rejette une version de format non supportée', async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    await expect(importRecoveryFile({ ...file, version: 99 }, 'mot-de-passe')).rejects.toThrow(
      InvalidEnvelopeError,
    );
  });

  it("rejette un algorithme de KDF non supporté", async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    // Simule un fichier corrompu/d'une version future — cast nécessaire, le champ est
    // volontairement invalide vis-à-vis du type `RecoveryFile`.
    const modifie = { ...file, kdf: { ...file.kdf, algo: 'scrypt' } } as unknown as RecoveryFile;

    await expect(importRecoveryFile(modifie, 'mot-de-passe')).rejects.toThrow(
      InvalidEnvelopeError,
    );
  });
});
