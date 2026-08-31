import sodium from 'libsodium-wrappers-sumo';

let readyPromise: Promise<typeof sodium> | undefined;

/**
 * Build "sumo" de libsodium (~400 Ko de WASM de plus que `sodium.ts`) : seule variante à
 * exposer `crypto_pwhash` (Argon2id), nécessaire pour `recovery.ts`. Isolé dans son propre
 * module pour que le bundle du portail (qui n'utilise jamais `recovery.ts`) n'embarque pas
 * ce poids pour rien.
 */
export function getSodiumSumo(): Promise<typeof sodium> {
  readyPromise ??= sodium.ready.then(() => sodium);
  return readyPromise;
}
