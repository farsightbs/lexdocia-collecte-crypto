import { describe, expect, it } from 'vitest';
import { generateAvocatKeyPair } from './keys.js';
import { decryptFile, encryptFile } from './envelope.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';
import type { AvocatKeyPair, RecipientPrivateKeys, RecipientPublicKeys } from './types.js';

/** `crypto.getRandomValues` refuse plus de 65 536 octets par appel — on remplit par blocs. */
function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  const CHUNK = 65_536;
  for (let offset = 0; offset < length; offset += CHUNK) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + CHUNK, length)));
  }
  return bytes;
}

function toPublicKeys(keyPair: AvocatKeyPair): RecipientPublicKeys {
  return {
    x25519PublicKey: keyPair.x25519.publicKey,
    mlkemPublicKey: keyPair.mlkem.publicKey,
  };
}

function toPrivateKeys(keyPair: AvocatKeyPair): RecipientPrivateKeys {
  return {
    x25519PrivateKey: keyPair.x25519.privateKey,
    mlkemPrivateKey: keyPair.mlkem.privateKey,
  };
}

describe('encryptFile / decryptFile', () => {
  it('fait un aller-retour fidèle sur un fichier non vide', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = new TextEncoder().encode('Pièce jointe confidentielle — dossier client.');

    const encrypted = await encryptFile(plaintext, toPublicKeys(avocat));
    const decrypted = await decryptFile(encrypted, toPrivateKeys(avocat));

    expect(decrypted).toEqual(plaintext);
  });

  it('fait un aller-retour fidèle sur un fichier vide', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = new Uint8Array(0);

    const encrypted = await encryptFile(plaintext, toPublicKeys(avocat));
    const decrypted = await decryptFile(encrypted, toPrivateKeys(avocat));

    expect(decrypted).toEqual(plaintext);
  });

  it('fait un aller-retour fidèle sur un binaire de plusieurs Mo', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = randomBytes(3 * 1024 * 1024);

    const encrypted = await encryptFile(plaintext, toPublicKeys(avocat));
    const decrypted = await decryptFile(encrypted, toPrivateKeys(avocat));

    expect(decrypted).toEqual(plaintext);
  });

  it('produit un chiffré et une clé encapsulée différents à chaque appel (nonces/éphémères non réutilisés)', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = new TextEncoder().encode('même contenu');

    const first = await encryptFile(plaintext, toPublicKeys(avocat));
    const second = await encryptFile(plaintext, toPublicKeys(avocat));

    expect(first.ciphertext).not.toEqual(second.ciphertext);
    expect(first.encapsulatedKey).not.toEqual(second.encapsulatedKey);
  });

  it("refuse de déchiffrer avec les clés privées d'un autre avocat", async () => {
    const destinataire = await generateAvocatKeyPair();
    const autreAvocat = await generateAvocatKeyPair();
    const plaintext = new TextEncoder().encode('confidentiel');

    const encrypted = await encryptFile(plaintext, toPublicKeys(destinataire));

    await expect(decryptFile(encrypted, toPrivateKeys(autreAvocat))).rejects.toThrow(
      DecryptionError,
    );
  });

  it('détecte une altération du blob chiffré (bit-flip)', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = new TextEncoder().encode('contenu à protéger');
    const encrypted = await encryptFile(plaintext, toPublicKeys(avocat));

    const tampered = new Uint8Array(encrypted.ciphertext);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff;

    await expect(
      decryptFile({ ...encrypted, ciphertext: tampered }, toPrivateKeys(avocat)),
    ).rejects.toThrow(DecryptionError);
  });

  it('détecte une altération de la clé de fichier encapsulée (bit-flip)', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = new TextEncoder().encode('contenu à protéger');
    const encrypted = await encryptFile(plaintext, toPublicKeys(avocat));

    const tampered = new Uint8Array(encrypted.encapsulatedKey);
    tampered[10] = tampered[10]! ^ 0xff;

    await expect(
      decryptFile({ ...encrypted, encapsulatedKey: tampered }, toPrivateKeys(avocat)),
    ).rejects.toThrow();
  });

  it('rejette une clé encapsulée de taille invalide sans tenter de déchiffrer', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = new TextEncoder().encode('x');
    const encrypted = await encryptFile(plaintext, toPublicKeys(avocat));

    await expect(
      decryptFile(
        { ...encrypted, encapsulatedKey: encrypted.encapsulatedKey.subarray(0, 10) },
        toPrivateKeys(avocat),
      ),
    ).rejects.toThrow(InvalidEnvelopeError);
  });

  it('rejette un blob chiffré tronqué', async () => {
    const avocat = await generateAvocatKeyPair();
    const plaintext = new TextEncoder().encode('x');
    const encrypted = await encryptFile(plaintext, toPublicKeys(avocat));

    await expect(
      decryptFile(
        { ...encrypted, ciphertext: encrypted.ciphertext.subarray(0, 5) },
        toPrivateKeys(avocat),
      ),
    ).rejects.toThrow(InvalidEnvelopeError);
  });
});
