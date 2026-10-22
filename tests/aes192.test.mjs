import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, webcrypto } from "node:crypto";
import { runTask, MAX_BYTES } from "../src/core.mjs";
test("AES-192 works when native AES key import rejects 192 bits as Chromium does", async (t) => {
  const importKey = crypto.subtle.importKey;
  t.mock.method(crypto.subtle, "importKey", function(format, data, algorithm, ...args) {
    const name = typeof algorithm === "string" ? algorithm : algorithm.name;
    if (name.startsWith("AES-") && data.byteLength === 24) {
      throw new DOMException("192-bit AES keys are not supported", "NotSupportedError");
    }
    return importKey.call(this, format, data, algorithm, ...args);
  });
  for (const algorithm of ["AES-GCM", "AES-CBC", "AES-CTR"]) {
    const key = "31".repeat(24), input = "AES-192 compatibility 中文";
    const encrypted = await runTask({ tool: "aes", op: "encrypt", algorithm, key, input });
    assert.equal(JSON.parse(encrypted.output).bits, 192);
    assert.equal((await runTask({ tool: "aes", op: "decrypt", key, input: encrypted.output })).output, input);
  }
});
test("AES-192 decrypts externally generated ciphertext in every mode and binary encoding", async () => {
  for (const algorithm of ["AES-GCM", "AES-CBC", "AES-CTR"]) {
    const key = Buffer.alloc(24, 13), iv = Buffer.alloc(algorithm === "AES-GCM" ? 12 : 16, 17);
    const native = createCipheriv(algorithm.toLowerCase().replace("aes-", "aes-192-"), key, iv);
    if (algorithm === "AES-GCM") native.setAAD(Buffer.from("context"));
    let ciphertext = Buffer.concat([native.update("external 密文 🔑"), native.final()]);
    if (algorithm === "AES-GCM") ciphertext = Buffer.concat([ciphertext, native.getAuthTag()]);
    for (const format of ["hex", "base64", "base64url"]) {
      const decrypted = await runTask({ tool: "aes", op: "decrypt", algorithm, cipherFormat: "raw", binaryFormat: format, key: key.toString("hex"), iv: iv.toString("hex"), aad: "context", input: ciphertext.toString(format) });
      assert.equal(decrypted.output, "external 密文 🔑");
    }
  }
});
test("AES-192 password derivation preserves envelope and raw decryption compatibility", async () => {
  for (const algorithm of ["AES-GCM", "AES-CBC", "AES-CTR"]) {
    const job = { tool: "aes", op: "encrypt", algorithm, keyMode: "password", bits: 192, password: "synthetic-password-only", iterations: 1e3, input: "derived AES-192 🔒" };
    const envelope = await runTask(job);
    assert.equal(JSON.parse(envelope.output).bits, 192);
    assert.equal((await runTask({ tool: "aes", op: "decrypt", input: envelope.output, password: job.password })).output, job.input);
    const raw = await runTask({ ...job, cipherFormat: "raw", binaryFormat: "hex" });
    assert.equal((await runTask({ ...job, op: "decrypt", cipherFormat: "raw", binaryFormat: "hex", iv: raw.params.iv, salt: raw.params.salt, input: raw.output })).output, job.input);
  }
});
test("AES-192 CTR keeps the high nonce bits unchanged when the 64-bit counter wraps", async () => {
  const rawKey = new Uint8Array(24).fill(23);
  const key = await webcrypto.subtle.importKey("raw", rawKey, "AES-CTR", false, ["encrypt"]);
  for (const hex of ["1234567890abcdeffffffffffffffffe", "1234567890abcdef00000000fffffffe"]) {
    const counter = Buffer.from(hex, "hex"), plain = Buffer.from("x".repeat(71));
    const ciphertext = await webcrypto.subtle.encrypt({ name: "AES-CTR", counter, length: 64 }, key, plain);
    const decrypted = await runTask({ tool: "aes", op: "decrypt", algorithm: "AES-CTR", key: Buffer.from(rawKey).toString("hex"), cipherFormat: "raw", binaryFormat: "hex", iv: hex, input: Buffer.from(ciphertext).toString("hex") });
    assert.equal(decrypted.output, plain.toString());
  }
});
test("AES-192 GCM authentication and CBC padding errors stay failures", async () => {
  const key = "13".repeat(24), job = { tool: "aes", op: "encrypt", algorithm: "AES-GCM", cipherFormat: "raw", key, aad: "context", input: "authenticated content" };
  const encrypted = await runTask(job), ciphertext = Buffer.from(encrypted.output, "base64");
  ciphertext[ciphertext.length - 1] ^= 1;
  await assert.rejects(runTask({ ...job, op: "decrypt", iv: encrypted.params.iv, input: ciphertext.toString("base64") }), /解密失败/);
  await assert.rejects(runTask({ ...job, op: "decrypt", iv: encrypted.params.iv, input: encrypted.output, aad: "wrong context" }), /解密失败/);
  await assert.rejects(runTask({ ...job, op: "decrypt", iv: encrypted.params.iv, input: encrypted.output, key: "14".repeat(24) }), /解密失败/);
  await assert.rejects(runTask({ tool: "aes", op: "decrypt", algorithm: "AES-CBC", cipherFormat: "raw", key, iv: "00".repeat(16), input: "00", binaryFormat: "hex" }), /解密失败/);
  await assert.rejects(runTask({ ...job, key: "13".repeat(23) }), /16 \/ 24 \/ 32/);
});
test("AES-192 handles empty, partial-block and maximum-size inputs", async () => {
  for (const algorithm of ["AES-GCM", "AES-CBC", "AES-CTR"]) {
    const key = "15".repeat(24);
    for (const input of ["", "a".repeat(16), "a".repeat(17), "a".repeat(MAX_BYTES)]) {
      const encrypted = await runTask({ tool: "aes", op: "encrypt", algorithm, key, input });
      assert.equal((await runTask({ tool: "aes", op: "decrypt", key, input: encrypted.output })).output, input);
    }
  }
});
