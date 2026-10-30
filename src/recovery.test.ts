import { describe, expect, it } from 'vitest';
import { generateAvocatKeyPair } from './keys.js';
import { exportRecoveryFile, importRecoveryFile, type RecoveryFile } from './recovery.js';
import { getSodiumSumo } from './sodium-sumo.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
import type { AvocatKeyPair, RecipientPrivateKeys } from './types.js';

function toPrivateKeys(keyPair: AvocatKeyPair): RecipientPrivateKeys {
  return { privateKey: keyPair.privateKey };
}

/** OPSLIMIT/MEMLIMIT minimaux valides pour libsodium — évite le coût "sensitive" en tests. */
const FAST_LIMITS = { opslimit: 1, memlimit: 8192 };

describe('exportRecoveryFile / importRecoveryFile', () => {
  it('fait un aller-retour fidèle sur les clés privées avec le bon mot de passe', async () => {
    const avocat = await generateAvocatKeyPair();
    const keys = toPrivateKeys(avocat);

    const file = await exportRecoveryFile(keys, 'mot-de-passe-avocat', FAST_LIMITS);
    const restored = await importRecoveryFile(file, 'mot-de-passe-avocat');

    expect(restored.privateKey).toEqual(keys.privateKey);
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

  it('rejette un nonce altéré', async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    const corrompu = { ...file, nonce: file.nonce.slice(0, -4) + 'AAAA' };

    await expect(importRecoveryFile(corrompu, 'mot-de-passe')).rejects.toThrow(DecryptionError);
  });

  it('rejette un sel altéré (autre clé dérivée)', async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    const corrompu = { ...file, kdf: { ...file.kdf, salt: 'A'.repeat(file.kdf.salt.length) } };

    await expect(importRecoveryFile(corrompu, 'mot-de-passe')).rejects.toThrow(DecryptionError);
  });

  it('rejette des paramètres Argon2id modifiés (autre clé dérivée)', async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    const corrompu = { ...file, kdf: { ...file.kdf, opslimit: file.kdf.opslimit + 1 } };

    await expect(importRecoveryFile(corrompu, 'mot-de-passe')).rejects.toThrow(DecryptionError);
  });

  it('rejette un ciphertext tronqué', async () => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    const corrompu = { ...file, ciphertext: file.ciphertext.slice(0, 20) };

    await expect(importRecoveryFile(corrompu, 'mot-de-passe')).rejects.toThrow(DecryptionError);
  });

  it('rejette un contenu authentique mais de taille inattendue', async () => {
    const sodium = await getSodiumSumo();
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const nonce = sodium.randombytes_buf(24);
    const key = sodium.crypto_pwhash(
      32,
      'mot-de-passe',
      salt,
      FAST_LIMITS.opslimit,
      FAST_LIMITS.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      new Uint8Array(10),
      null,
      null,
      nonce,
      key,
    );
    const file: RecoveryFile = {
      version: 1,
      kdf: { algo: 'argon2id', salt: sodium.to_base64(salt), ...FAST_LIMITS },
      nonce: sodium.to_base64(nonce),
      ciphertext: sodium.to_base64(ciphertext),
    };

    await expect(importRecoveryFile(file, 'mot-de-passe')).rejects.toThrow(InvalidEnvelopeError);
  });

  it.each(['salt', 'nonce', 'ciphertext'] as const)(
    'rejette un base64 invalide dans %s avec une erreur typée',
    async (champ) => {
      const avocat = await generateAvocatKeyPair();
      const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

      const corrompu =
        champ === 'salt'
          ? { ...file, kdf: { ...file.kdf, salt: '!!!' } }
          : { ...file, [champ]: '!!!' };

      await expect(importRecoveryFile(corrompu, 'mot-de-passe')).rejects.toThrow(
        InvalidEnvelopeError,
      );
    },
  );

  it.each([
    ['sel vide', { salt: '' }],
    ['nonce de taille invalide', { nonce: 'AAAA' }],
  ] as const)('rejette un fichier avec un %s avec une erreur typée', async (_nom, champ) => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);
    const corrompu =
      'salt' in champ
        ? { ...file, kdf: { ...file.kdf, salt: champ.salt } }
        : { ...file, nonce: champ.nonce };

    await expect(importRecoveryFile(corrompu, 'mot-de-passe')).rejects.toThrow(InvalidEnvelopeError);
  });

  it.each([
    ['memlimit démesuré', { memlimit: 2 ** 40 }],
    ['opslimit démesuré', { opslimit: 2 ** 31 }],
    ['opslimit nul', { opslimit: 0 }],
    ['memlimit non entier', { memlimit: 8192.5 }],
  ] as const)('rejette des paramètres Argon2id hors limites (%s) sans calcul', async (_nom, kdf) => {
    const avocat = await generateAvocatKeyPair();
    const file = await exportRecoveryFile(toPrivateKeys(avocat), 'mot-de-passe', FAST_LIMITS);

    await expect(
      importRecoveryFile({ ...file, kdf: { ...file.kdf, ...kdf } }, 'mot-de-passe'),
    ).rejects.toThrow(InvalidEnvelopeError);
  });
});
