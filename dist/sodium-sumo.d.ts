import sodium from 'libsodium-wrappers-sumo';
/**
 * Build "sumo" de libsodium (~400 Ko de WASM de plus que `sodium.ts`) : seule variante à
 * exposer `crypto_pwhash` (Argon2id), nécessaire pour `recovery.ts`. Isolé dans son propre
 * module pour que le bundle du portail (qui n'utilise jamais `recovery.ts`) n'embarque pas
 * ce poids pour rien.
 */
export declare function getSodiumSumo(): Promise<typeof sodium>;
