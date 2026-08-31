import sodium from 'libsodium-wrappers';
let readyPromise;
/** libsodium-wrappers doit finir son init WASM (`sodium.ready`) avant le premier appel. */
export function getSodium() {
    readyPromise ??= sodium.ready.then(() => sodium);
    return readyPromise;
}
//# sourceMappingURL=sodium.js.map