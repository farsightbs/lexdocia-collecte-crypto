import sodium from 'libsodium-wrappers';
/** libsodium-wrappers doit finir son init WASM (`sodium.ready`) avant le premier appel. */
export declare function getSodium(): Promise<typeof sodium>;
