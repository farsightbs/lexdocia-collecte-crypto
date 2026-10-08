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
import { DecryptionError, InvalidEnvelopeError } from './errors.js';

const secret = (octet: number) => new Uint8Array(32).fill(octet);

async function nouvelleCle() {
  const kp = await generateAvocatKeyPair();
  return {
    pub: { x25519PublicKey: kp.x25519.publicKey, mlkemPublicKey: kp.mlkem.publicKey },
    priv: { x25519PrivateKey: kp.x25519.privateKey, mlkemPrivateKey: kp.mlkem.privateKey },
  };
}

describe('sealPrivateKeys / openPrivateKeys', () => {
  it('restitue les clés privées avec le même secret de passkey', async () => {
    const { priv } = await nouvelleCle();
    const sealed = await sealPrivateKeys(priv, secret(7));
    expect(sealed.length).toBe(SEALED_PRIVATE_KEYS_LENGTH);

    const ouvert = await openPrivateKeys(sealed, secret(7));
    expect(ouvert.x25519PrivateKey).toEqual(priv.x25519PrivateKey);
    expect(ouvert.mlkemPrivateKey).toEqual(priv.mlkemPrivateKey);
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
    altere[100] = (altere[100] ?? 0) ^ 0xff;
    await expect(openPrivateKeys(altere, secret(7))).rejects.toBeInstanceOf(DecryptionError);
    await expect(openPrivateKeys(sealed.slice(0, 50), secret(7))).rejects.toBeInstanceOf(
      InvalidEnvelopeError,
    );
  });

  it('refuse un secret de taille invalide', async () => {
    const { priv } = await nouvelleCle();
    await expect(sealPrivateKeys(priv, new Uint8Array(16))).rejects.toBeInstanceOf(
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
});
