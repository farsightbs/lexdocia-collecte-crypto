import { describe, expect, it } from 'vitest';
import { generateAvocatKeyPair } from './keys.js';
import { decryptFile, encryptFile } from './envelope.js';
import { xwingDecapsulate, xwingEncapsulate } from './hybrid-kem.js';
import {
  ENCAPSULATED_KEY_LENGTH,
  XWING_CIPHERTEXT_BYTES,
  XCHACHA20POLY1305_NONCE_BYTES,
  XCHACHA20POLY1305_TAG_BYTES,
} from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
import type { AvocatKeyPair, EncryptedFile, RecipientPrivateKeys, RecipientPublicKeys } from './types.js';

function toPublicKeys(keyPair: AvocatKeyPair): RecipientPublicKeys {
  return { publicKey: keyPair.publicKey };
}

function toPrivateKeys(keyPair: AvocatKeyPair): RecipientPrivateKeys {
  return { privateKey: keyPair.privateKey };
}

const CIPHERTEXT_HEADER_LENGTH = 1 + XCHACHA20POLY1305_NONCE_BYTES;

/** Début de chaque zone de la clé encapsulée (cf. layout dans `constants.ts`). */
const ZONES_CLE_ENCAPSULEE = {
  'ciphertext ML-KEM (début du ciphertext X-Wing)': 1,
  'clé X25519 éphémère (fin du ciphertext X-Wing)': 1 + XWING_CIPHERTEXT_BYTES - 32,
  'nonce de la clé enveloppée': 1 + XWING_CIPHERTEXT_BYTES,
  'clé de fichier enveloppée': 1 + XWING_CIPHERTEXT_BYTES + XCHACHA20POLY1305_NONCE_BYTES,
};

async function chiffrer(contenu = 'contenu à protéger') {
  const avocat = await generateAvocatKeyPair();
  const encrypted = await encryptFile(new TextEncoder().encode(contenu), toPublicKeys(avocat));
  return { avocat, encrypted };
}

function avecOctetInverse(octets: Uint8Array, index: number): Uint8Array {
  const copie = new Uint8Array(octets);
  copie[index] = copie[index]! ^ 0x01;
  return copie;
}

describe('altération de la clé encapsulée, zone par zone', () => {
  for (const [zone, debut] of Object.entries(ZONES_CLE_ENCAPSULEE)) {
    it(`rejette un bit modifié dans : ${zone}`, async () => {
      const { avocat, encrypted } = await chiffrer();
      const altere = avecOctetInverse(encrypted.encapsulatedKey, debut + 3);

      await expect(
        decryptFile({ ...encrypted, encapsulatedKey: altere }, toPrivateKeys(avocat)),
      ).rejects.toBeInstanceOf(DecryptionError);
    });
  }

  it('rejette le dernier octet (tag de la clé enveloppée)', async () => {
    const { avocat, encrypted } = await chiffrer();
    const altere = avecOctetInverse(encrypted.encapsulatedKey, ENCAPSULATED_KEY_LENGTH - 1);

    await expect(
      decryptFile({ ...encrypted, encapsulatedKey: altere }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('altération du blob chiffré, zone par zone', () => {
  it('rejette un bit modifié dans le nonce', async () => {
    const { avocat, encrypted } = await chiffrer();
    const altere = avecOctetInverse(encrypted.ciphertext, 1);

    await expect(
      decryptFile({ ...encrypted, ciphertext: altere }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejette un bit modifié dans le contenu chiffré', async () => {
    const { avocat, encrypted } = await chiffrer();
    const altere = avecOctetInverse(encrypted.ciphertext, CIPHERTEXT_HEADER_LENGTH);

    await expect(
      decryptFile({ ...encrypted, ciphertext: altere }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejette un bit modifié dans le tag', async () => {
    const { avocat, encrypted } = await chiffrer();
    const altere = avecOctetInverse(encrypted.ciphertext, encrypted.ciphertext.length - 1);

    await expect(
      decryptFile({ ...encrypted, ciphertext: altere }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejette un blob chiffré dont la fin a été coupée', async () => {
    const { avocat, encrypted } = await chiffrer();
    const coupe = encrypted.ciphertext.subarray(0, encrypted.ciphertext.length - 1);

    await expect(
      decryptFile({ ...encrypted, ciphertext: coupe }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('version de format', () => {
  it('rejette une version inconnue dans le blob chiffré', async () => {
    const { avocat, encrypted } = await chiffrer();
    const altere = new Uint8Array(encrypted.ciphertext);
    altere[0] = 99;

    await expect(
      decryptFile({ ...encrypted, ciphertext: altere }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(InvalidEnvelopeError);
  });

  it('rejette une version inconnue dans la clé encapsulée', async () => {
    const { avocat, encrypted } = await chiffrer();
    const altere = new Uint8Array(encrypted.encapsulatedKey);
    altere[0] = 99;

    await expect(
      decryptFile({ ...encrypted, encapsulatedKey: altere }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(InvalidEnvelopeError);
  });
});

describe('limites de longueur du blob chiffré', () => {
  const MINIMUM = CIPHERTEXT_HEADER_LENGTH + XCHACHA20POLY1305_TAG_BYTES;

  it('rejette un blob d\'un octet sous le minimum (en-tête + tag)', async () => {
    const { avocat, encrypted } = await chiffrer();
    const trop_court = encrypted.ciphertext.subarray(0, MINIMUM - 1);

    await expect(
      decryptFile({ ...encrypted, ciphertext: trop_court }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(InvalidEnvelopeError);
  });

  it('accepte le minimum exact : un fichier vide donne en-tête + tag', async () => {
    const avocat = await generateAvocatKeyPair();
    const encrypted = await encryptFile(new Uint8Array(0), toPublicKeys(avocat));

    expect(encrypted.ciphertext.length).toBe(MINIMUM);
    expect(await decryptFile(encrypted, toPrivateKeys(avocat))).toEqual(new Uint8Array(0));
  });

  it('rejette une clé encapsulée trop longue d\'un octet', async () => {
    const { avocat, encrypted } = await chiffrer();
    const trop_longue = new Uint8Array(ENCAPSULATED_KEY_LENGTH + 1);
    trop_longue.set(encrypted.encapsulatedKey);

    await expect(
      decryptFile({ ...encrypted, encapsulatedKey: trop_longue }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(InvalidEnvelopeError);
  });
});

describe('mélange de pièces entre deux chiffrements', () => {
  it('rejette le blob du fichier A avec la clé encapsulée du fichier B', async () => {
    const avocat = await generateAvocatKeyPair();
    const a = await encryptFile(new TextEncoder().encode('A'), toPublicKeys(avocat));
    const b = await encryptFile(new TextEncoder().encode('B'), toPublicKeys(avocat));

    await expect(
      decryptFile(
        { ciphertext: a.ciphertext, encapsulatedKey: b.encapsulatedKey },
        toPrivateKeys(avocat),
      ),
    ).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejette un blob chiffré pour un autre destinataire, même avec la bonne clé encapsulée', async () => {
    const avocat = await generateAvocatKeyPair();
    const autre = await generateAvocatKeyPair();
    const mien = await encryptFile(new TextEncoder().encode('A'), toPublicKeys(avocat));
    const etranger = await encryptFile(new TextEncoder().encode('B'), toPublicKeys(autre));

    const melange: EncryptedFile = {
      ciphertext: etranger.ciphertext,
      encapsulatedKey: mien.encapsulatedKey,
    };
    await expect(decryptFile(melange, toPrivateKeys(avocat))).rejects.toBeInstanceOf(
      DecryptionError,
    );
  });
});

describe('clé privée incorrecte', () => {
  it("rejette la clé privée d'un autre destinataire", async () => {
    const { encrypted } = await chiffrer();
    const autre = await generateAvocatKeyPair();

    await expect(decryptFile(encrypted, toPrivateKeys(autre))).rejects.toBeInstanceOf(
      DecryptionError,
    );
  });

  it('rejette une clé privée de taille invalide avec une erreur typée', async () => {
    const { encrypted } = await chiffrer();

    await expect(decryptFile(encrypted, { privateKey: new Uint8Array(31) })).rejects.toBeInstanceOf(
      InvalidEnvelopeError,
    );
  });
});

describe('chiffrement : clé publique invalide', () => {
  it('rejette une clé publique de taille invalide', async () => {
    await expect(
      encryptFile(new Uint8Array(1), { publicKey: new Uint8Array(1184) }),
    ).rejects.toBeInstanceOf(InvalidEnvelopeError);
  });
});

describe('xwingDecapsulate : entrées forgées', () => {
  it('rejette un ciphertext de taille invalide', async () => {
    const avocat = await generateAvocatKeyPair();

    expect(() => xwingDecapsulate(new Uint8Array(10), avocat.privateKey)).toThrow(DecryptionError);
  });

  it('un ciphertext altéré ne donne pas le secret légitime (rejet implicite ML-KEM)', async () => {
    const avocat = await generateAvocatKeyPair();
    const { cipherText, sharedSecret } = xwingEncapsulate(avocat.publicKey);
    const altere = avecOctetInverse(cipherText, 10);

    expect(xwingDecapsulate(altere, avocat.privateKey)).not.toEqual(sharedSecret);
  });

  it('rejette via decryptFile une partie X25519 du ciphertext mise à zéro', async () => {
    const { avocat, encrypted } = await chiffrer();
    const forge = new Uint8Array(encrypted.encapsulatedKey);
    forge.fill(0, 1 + XWING_CIPHERTEXT_BYTES - 32, 1 + XWING_CIPHERTEXT_BYTES);

    await expect(
      decryptFile({ ...encrypted, encapsulatedKey: forge }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('format v1 abandonné', () => {
  it('rejette une enveloppe marquée version 1', async () => {
    const { avocat, encrypted } = await chiffrer();
    const v1 = new Uint8Array(encrypted.encapsulatedKey);
    v1[0] = 1;

    await expect(
      decryptFile({ ...encrypted, encapsulatedKey: v1 }, toPrivateKeys(avocat)),
    ).rejects.toBeInstanceOf(InvalidEnvelopeError);
  });
});
