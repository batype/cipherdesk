import { cbc, ctr, gcm } from "@noble/ciphers/aes.js";
export function aes192(mode, key, iv, aad) {
  if (mode === "AES-GCM") return gcm(key, iv, aad);
  if (mode === "AES-CBC") return cbc(key, iv);
  const transform = (data) => {
    const counter = new DataView(iv.buffer, iv.byteOffset, iv.byteLength).getBigUint64(8);
    const blocksBeforeWrap = (1n << 64n) - counter;
    if (BigInt(Math.ceil(data.length / 16)) <= blocksBeforeWrap) {
      return ctr(key, iv).encrypt(data);
    }
    const split = Number(blocksBeforeWrap) * 16;
    const wrapped = iv.slice();
    wrapped.fill(0, 8);
    const output = new Uint8Array(data.length);
    output.set(ctr(key, iv).encrypt(data.subarray(0, split)));
    output.set(ctr(key, wrapped).encrypt(data.subarray(split)), split);
    return output;
  };
  return { encrypt: transform, decrypt: transform };
}
