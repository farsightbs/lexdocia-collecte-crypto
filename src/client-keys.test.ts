import { describe, expect, it } from 'vitest';
import { generateAvocatKeyPair } from './keys.js';
import { encryptFile, decryptFile } from './envelope.js';
import {
  SEALED_PRIVATE_KEYS_LENGTH,
  decryptJson,
  encryptJson,
  fingerprintPublicKeys,
  openPrivateKeys,
  sealPrivateKeys,
} from './client-keys.js';
import { FORMAT_VERSION, XCHACHA20POLY1305_NONCE_BYTES } from './constants.js';
import { DecryptionError, InvalidEnvelopeError } from './errors.js';

const secret = (octet: number) => new Uint8Array(32).fill(octet);

async function nouvelleCle() {
  const kp = await generateAvocatKeyPair();
  return {
    pub: { publicKey: kp.publicKey },
    priv: { privateKey: kp.privateKey },
  };
}

describe('sealPrivateKeys / openPrivateKeys', () => {
  it('restitue les clés privées avec le même secret de passkey', async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    expect(sealed.length).toBe(SEALED_PRIVATE_KEYS_LENGTH);

    const ouvert = await openPrivateKeys(sealed, secret(7));
    expect(ouvert.privateKey).toEqual(priv.privateKey);
  });

  it("refuse un autre secret (autre passkey)", async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    await expect(openPrivateKeys(sealed, secret(8))).rejects.toBeInstanceOf(DecryptionError);
  });

  it('refuse un blob altéré ou de taille invalide', async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    const altere = sealed.slice();
    altere[40] = (altere[40] ?? 0) ^ 0xff;
    await expect(openPrivateKeys(altere, secret(7))).rejects.toBeInstanceOf(DecryptionError);
    await expect(openPrivateKeys(sealed.slice(0, 50), secret(7))).rejects.toBeInstanceOf(
      InvalidEnvelopeError,
    );
  });

  it('refuse une clé privée de taille invalide', async () => {
    await expect(
      sealPrivateKeys({ privateKey: new Uint8Array(31) }, secret(7)),
    ).rejects.toBeInstanceOf(InvalidEnvelopeError);
  });

  it('refuse un secret de taille invalide', async () => {
    const { priv } = await nouvelleCle();
    await expect(sealPrivateKeys(priv, new Uint8Array(16))).rejects.toBeInstanceOf(
      InvalidEnvelopeError,
    );
  });

  it('refuse une version de format inconnue', async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    const autreVersion = sealed.slice();
    autreVersion[0] = FORMAT_VERSION + 1;
    await expect(openPrivateKeys(autreVersion, secret(7))).rejects.toBeInstanceOf(
      InvalidEnvelopeError,
    );
  });

  it('refuse un blob altéré dans le nonce, au début, au milieu et dans le tag', async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    const positions = [1, XCHACHA20POLY1305_NONCE_BYTES + 1, 40, sealed.length - 1];
    for (const position of positions) {
      const altere = sealed.slice();
      altere[position] = (altere[position] ?? 0) ^ 0x01;
      await expect(openPrivateKeys(altere, secret(7))).rejects.toBeInstanceOf(DecryptionError);
    }
  });

  it('refuse un blob trop long d\'un octet', async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    const trop_long = new Uint8Array(sealed.length + 1);
    trop_long.set(sealed);
    await expect(openPrivateKeys(trop_long, secret(7))).rejects.toBeInstanceOf(
      InvalidEnvelopeError,
    );
  });

  it('refuse d\'ouvrir avec un secret de taille invalide', async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    await expect(openPrivateKeys(sealed, new Uint8Array(33))).rejects.toBeInstanceOf(
      InvalidEnvelopeError,
    );
  });

  it("produit un blob différent à chaque scellement (nonce aléatoire)", async () => {
    const { priv } = await nouvelleCle();
    const a = await sealPrivateKeys(priv, secret(1));
    const b = await sealPrivateKeys(priv, secret(1));
    expect(a).not.toEqual(b);
  });
});

describe('flux avocat → client', () => {
  it("l'avocat chiffre pour le client, le client déchiffre avec ses clés ouvertes par la passkey", async () => {
    const client = await nouvelleCle();
    const sealed = await sealPrivateKeys(client.priv, secret(42));

    const contenu = new TextEncoder().encode('Pièce n°1 — contenu confidentiel');
    const envoye = await encryptFile(contenu, client.pub);

    const cles = await openPrivateKeys(sealed, secret(42));
    expect(await decryptFile(envoye, cles)).toEqual(contenu);
  });
});

describe('fingerprintPublicKeys', () => {
  it('est stable pour les mêmes clés et formatée en 8 groupes de 4 caractères hexadécimaux', async () => {
    const { pub } = await nouvelleCle();
    const a = await fingerprintPublicKeys(pub);
    expect(a).toMatch(/^([0-9a-f]{4} ){7}[0-9a-f]{4}$/);
    expect(await fingerprintPublicKeys(pub)).toBe(a);
  });

  it('change dès que les clés changent', async () => {
    const x = await nouvelleCle();
    const y = await nouvelleCle();
    expect(await fingerprintPublicKeys(x.pub)).not.toBe(await fingerprintPublicKeys(y.pub));
  });
});

describe('encryptJson / decryptJson', () => {
  it('aller-retour des métadonnées', async () => {
    const { pub, priv } = await nouvelleCle();
    const meta = { nom: 'Pièce 3 – Contrat de bail.pdf', mimeType: 'application/pdf' };
    const chiffre = await encryptJson(meta, pub);
    expect(await decryptJson(chiffre, priv)).toEqual(meta);
  });

  it('refuse des métadonnées altérées', async () => {
    const { pub, priv } = await nouvelleCle();
    const chiffre = await encryptJson({ nom: 'contrat.pdf' }, pub);
    const altere = chiffre.ciphertext.slice();
    altere[altere.length - 1] = (altere[altere.length - 1] ?? 0) ^ 0x01;
    await expect(
      decryptJson({ ...chiffre, ciphertext: altere }, priv),
    ).rejects.toBeInstanceOf(DecryptionError);
  });

  it("refuse des métadonnées chiffrées pour un autre destinataire", async () => {
    const destinataire = await nouvelleCle();
    const autre = await nouvelleCle();
    const chiffre = await encryptJson({ nom: 'contrat.pdf' }, destinataire.pub);
    await expect(decryptJson(chiffre, autre.priv)).rejects.toBeInstanceOf(DecryptionError);
  });

  it("lève une erreur sur un contenu authentique qui n'est pas du JSON", async () => {
    const { pub, priv } = await nouvelleCle();
    const chiffre = await encryptFile(new TextEncoder().encode('pas du json {'), pub);
    await expect(decryptJson(chiffre, priv)).rejects.toThrow(SyntaxError);
  });
});
