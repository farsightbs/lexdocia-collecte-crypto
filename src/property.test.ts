import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { generateAvocatKeyPair } from './keys.js';
import { decryptFile, encryptFile } from './envelope.js';
import { SEALED_PRIVATE_KEYS_LENGTH, openPrivateKeys, sealPrivateKeys } from './client-keys.js';
import { exportRecoveryFile, importRecoveryFile, type RecoveryFile } from './recovery.js';
import {
  ENCAPSULATED_KEY_LENGTH,
  XCHACHA20POLY1305_NONCE_BYTES,
  XWING_CIPHERTEXT_BYTES,
} from './constants.js';
import { CollecteCryptoError } from './errors.js';
import type { AvocatKeyPair, RecipientPrivateKeys, RecipientPublicKeys } from './types.js';

/**
 * Tests de propriété et fuzzing léger. Une propriété doit tenir pour toute entrée, pas seulement pour les
 * exemples écrits à la main. En cas d'échec, fast-check affiche la graine (`seed`) et le contre-exemple minimal :
 * relancer avec `fc.assert(..., { seed })` pour le reproduire.
 */

let avocat: AvocatKeyPair;
let publiques: RecipientPublicKeys;
let privees: RecipientPrivateKeys;

beforeAll(async () => {
  avocat = await generateAvocatKeyPair();
  publiques = { publicKey: avocat.publicKey };
  privees = { privateKey: avocat.privateKey };
});

const octets = (min: number, max: number) => fc.uint8Array({ minLength: min, maxLength: max });

/** Une promesse qui doit être rejetée par une erreur typée de la bibliothèque, jamais par une erreur brute. */
async function rejetteProprement(promesse: Promise<unknown>): Promise<boolean> {
  try {
    await promesse;
    return false;
  } catch (erreur) {
    return erreur instanceof CollecteCryptoError;
  }
}

describe('propriétés du chiffrement de fichier', () => {
  it('decrypt(encrypt(x)) === x pour tout contenu', async () => {
    await fc.assert(
      fc.asyncProperty(octets(0, 4096), async (clair) => {
        const chiffre = await encryptFile(clair, publiques);
        const dechiffre = await decryptFile(chiffre, privees);
        expect(dechiffre).toEqual(clair);
      }),
      { numRuns: 100 },
    );
  });

  it('la taille du chiffré est celle du clair plus une surcharge constante', async () => {
    await fc.assert(
      fc.asyncProperty(octets(0, 2048), async (clair) => {
        const a = await encryptFile(clair, publiques);
        const b = await encryptFile(new Uint8Array(0), publiques);
        expect(a.ciphertext.length - clair.length).toBe(b.ciphertext.length);
        expect(a.encapsulatedKey.length).toBe(ENCAPSULATED_KEY_LENGTH);
      }),
      { numRuns: 50 },
    );
  });

  it('modifier un seul bit, où que ce soit, est toujours détecté', async () => {
    const clair = new TextEncoder().encode('contenu confidentiel du dossier');
    const chiffre = await encryptFile(clair, publiques);

    await fc.assert(
      fc.asyncProperty(
        fc.boolean(),
        fc.nat(),
        fc.integer({ min: 0, max: 7 }),
        async (surLaCle, position, bit) => {
          const cible = surLaCle ? chiffre.encapsulatedKey : chiffre.ciphertext;
          const altere = new Uint8Array(cible);
          const index = position % altere.length;
          altere[index] = altere[index]! ^ (1 << bit);

          const paquet = surLaCle
            ? { ...chiffre, encapsulatedKey: altere }
            : { ...chiffre, ciphertext: altere };
          expect(await rejetteProprement(decryptFile(paquet, privees))).toBe(true);
        },
      ),
      { numRuns: 300 },
    );
  });

  it("aucun bit de la partie X25519 du chiffré X-Wing n'est malléable", async () => {
    // X25519 ignore le bit de poids fort de la coordonnée u (RFC 7748 §5) : avec l'ancien hybride maison, retourner ce
    // bit laissait le déchiffrement réussir (échec aléatoire du test de propriété ci-dessus, ~1 % des exécutions).
    // X-Wing inclut ct_X25519 dans le combineur, donc tout bit modifié change le secret : on le vérifie exhaustivement.
    const chiffre = await encryptFile(new TextEncoder().encode('contenu'), publiques);
    const debutX25519 = 1 + XWING_CIPHERTEXT_BYTES - 32;
    for (let i = debutX25519; i < debutX25519 + 32; i++) {
      for (let bit = 0; bit < 8; bit++) {
        const altere = new Uint8Array(chiffre.encapsulatedKey);
        altere[i] = altere[i]! ^ (1 << bit);
        const paquet = { ...chiffre, encapsulatedKey: altere };
        expect(await rejetteProprement(decryptFile(paquet, privees))).toBe(true);
      }
    }
  });

  it('jamais deux chiffrements identiques ni de nonce réutilisé sur 500 appels', async () => {
    const clair = new TextEncoder().encode('même contenu');
    const nonces = new Set<string>();
    const cles = new Set<string>();
    const chiffres = new Set<string>();

    for (let i = 0; i < 500; i++) {
      const { ciphertext, encapsulatedKey } = await encryptFile(clair, publiques);
      nonces.add(ciphertext.subarray(1, 1 + XCHACHA20POLY1305_NONCE_BYTES).join(','));
      cles.add(encapsulatedKey.join(','));
      chiffres.add(ciphertext.join(','));
    }

    expect(nonces.size).toBe(500);
    expect(cles.size).toBe(500);
    expect(chiffres.size).toBe(500);
  });
});

describe('fuzzing : entrées arbitraires', () => {
  it('decryptFile rejette toujours avec une erreur typée, quelles que soient les entrées', async () => {
    await fc.assert(
      fc.asyncProperty(octets(0, 3000), octets(0, ENCAPSULATED_KEY_LENGTH + 64), async (ciphertext, cle) => {
        expect(await rejetteProprement(decryptFile({ ciphertext, encapsulatedKey: cle }, privees))).toBe(true);
      }),
      { numRuns: 300 },
    );
  });

  it("decryptFile rejette proprement une clé encapsulée de taille exacte mais de contenu aléatoire", async () => {
    const valide = await encryptFile(new TextEncoder().encode('x'), publiques);

    await fc.assert(
      fc.asyncProperty(octets(ENCAPSULATED_KEY_LENGTH, ENCAPSULATED_KEY_LENGTH), async (cle) => {
        // Version de format valide, le reste est aléatoire : on exerce la décapsulation hybride.
        cle[0] = 1;
        expect(
          await rejetteProprement(decryptFile({ ciphertext: valide.ciphertext, encapsulatedKey: cle }, privees)),
        ).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('openPrivateKeys rejette toujours avec une erreur typée', async () => {
    const secret = new Uint8Array(32).fill(3);

    await fc.assert(
      fc.asyncProperty(octets(0, SEALED_PRIVATE_KEYS_LENGTH + 32), async (blob) => {
        expect(await rejetteProprement(openPrivateKeys(blob, secret))).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('openPrivateKeys rejette un blob de taille exacte et de contenu aléatoire', async () => {
    const secret = new Uint8Array(32).fill(3);

    await fc.assert(
      fc.asyncProperty(octets(SEALED_PRIVATE_KEYS_LENGTH, SEALED_PRIVATE_KEYS_LENGTH), async (blob) => {
        blob[0] = 1;
        expect(await rejetteProprement(openPrivateKeys(blob, secret))).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('openPrivateKeys(seal(k, s), s) === k pour tout secret de 32 octets', async () => {
    await fc.assert(
      fc.asyncProperty(octets(32, 32), async (secret) => {
        const scelle = await sealPrivateKeys(privees, secret);
        const ouvert = await openPrivateKeys(scelle, secret);
        expect(ouvert.privateKey).toEqual(privees.privateKey);
      }),
      { numRuns: 50 },
    );
  });

  it('importRecoveryFile rejette toujours avec une erreur typée un fichier aux champs aléatoires', async () => {
    const valide = await exportRecoveryFile(privees, 'mot-de-passe', { opslimit: 1, memlimit: 8192 });
    // Chaînes arbitraires pour les trois champs encodés ; les paramètres Argon2id restent minimaux (valeurs
    // contrôlées par l'attaquant : voir la note dans la PR sur les limites).
    const champ = fc.oneof(fc.string({ maxLength: 64 }), fc.base64String({ maxLength: 64 }));

    await fc.assert(
      fc.asyncProperty(champ, champ, champ, async (salt, nonce, ciphertext) => {
        const fichier: RecoveryFile = { ...valide, kdf: { ...valide.kdf, salt }, nonce, ciphertext };
        expect(await rejetteProprement(importRecoveryFile(fichier, 'mot-de-passe'))).toBe(true);
      }),
      { numRuns: 100 },
    );
  });
});
