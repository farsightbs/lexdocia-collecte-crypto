import sodium from 'libsodium-wrappers';

let readyPromise: Promise<typeof sodium> | undefined;

/** libsodium-wrappers doit finir son init WASM (`sodium.ready`) avant le premier appel. */
export function getSodium(): Promise<typeof sodium> {
  readyPromise ??= sodium.ready.then(() => sodium);
  return readyPromise;
}
