import { md5 } from "@noble/hashes/legacy.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";
import sm3 from "sm-crypto/src/sm3/index.js";
import sm4 from "sm-crypto/src/sm4/index.js";
export const VERSION = "1.0.0", MAX_BYTES = 1024 * 1024;
const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
const fail = (message) => {
  throw new Error(message);
};
const text = (value) => {
  if (typeof value !== "string") fail("输入必须是字符串");
  if (encoder.encode(value).length > MAX_BYTES * 3) fail("文本超过 3 MiB，请拆分处理");
  return value;
};
const limit = (bytes, max = MAX_BYTES) => {
  if (bytes.length > max) fail("解码后输入最多 1 MiB");
  return bytes;
};
const subtle = () => {
  if (!globalThis.crypto?.subtle) fail("需要 HTTPS 或 localhost，以及支持 Web Crypto 的现代浏览器 / Node.js 22.14+");
  return crypto.subtle;
};
const integer = (value, min, max, label) => {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) fail(`${label}必须是 ${min}–${max} 的整数`);
  return n;
};
const hashName = (value) => {
  if (!["SHA-1", "SHA-256", "SHA-384", "SHA-512"].includes(value)) fail("不支持的 SHA 算法");
  return value;
};
export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
export function randomBytes(size) {
  size = integer(size, 1, 4096, "随机字节数");
  return crypto.getRandomValues(new Uint8Array(size));
}
export function encodeBytes(bytes, format = "base64") {
  if (format === "hex") return toHex(bytes);
  if (format === "utf8") {
    try {
      return decoder.decode(bytes);
    } catch {
      fail("结果不是有效 UTF-8，请选择 Hex 或 Base64 输出");
    }
  }
  if (!["base64", "base64url"].includes(format)) fail("未知字节输出格式");
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  const result2 = btoa(binary);
  return format === "base64url" ? result2.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : result2;
}
export function decodeBytes(input, format = "utf8", max = MAX_BYTES) {
  input = text(input);
  if (format === "utf8") {
    if (input.isWellFormed && !input.isWellFormed()) fail("输入包含不完整的 Unicode 字符");
    return limit(encoder.encode(input), max);
  }
  if (format === "hex") {
    const value2 = input.replace(/\s/g, "");
    if (value2.length % 2 || !/^[\da-f]*$/i.test(value2)) fail("Hex 必须为偶数个十六进制字符");
    return limit(Uint8Array.from(value2.match(/../g) ?? [], (x) => parseInt(x, 16)), max);
  }
  if (!["base64", "base64url"].includes(format)) fail("未知字节输入格式");
  const value = input.replace(/[\t\r\n ]/g, ""), url = format === "base64url";
  if (!(url ? /^[\w-]*={0,2}$/ : /^[A-Za-z0-9+/]*={0,2}$/).test(value) || value.length % 4 === 1 || value.includes("=") && value.length % 4 !== 0) fail("Base64 格式无效，请检查字符与末尾填充");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  let binary;
  try {
    binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  } catch {
    fail("Base64 解码失败");
  }
  const bytes = limit(Uint8Array.from(binary, (c) => c.charCodeAt(0)), max);
  if (encodeBytes(bytes, format).replace(/=+$/, "") !== value.replace(/=+$/, "")) fail("Base64 包含非规范的填充位");
  return bytes;
}
const result = (output, details = {}, params) => ({ output, details, ...params ? { params } : {} });
function pem(bytes, label) {
  return `-----BEGIN ${label}-----
${encodeBytes(bytes).match(/.{1,64}/g).join("\n")}
-----END ${label}-----`;
}
function pemBytes(value, label) {
  value = text(value).trim();
  const match = value.match(new RegExp(`^-----BEGIN ${label}-----\\s*([A-Za-z0-9+/=\\s]+)\\s*-----END ${label}-----$`));
  if (!match) fail(`需要 ${label} PEM（公钥 SPKI / 私钥未加密 PKCS#8），不接受 PKCS#1 或证书`);
  return decodeBytes(match[1], "base64");
}
async function rsaKey(value, privateKey, name = "RSA-OAEP") {
  const key = await subtle().importKey(privateKey ? "pkcs8" : "spki", pemBytes(value, privateKey ? "PRIVATE KEY" : "PUBLIC KEY"), { name, hash: "SHA-256" }, false, privateKey ? [name === "RSA-OAEP" ? "decrypt" : "sign"] : [name === "RSA-OAEP" ? "encrypt" : "verify"]);
  if (key.algorithm.modulusLength < 2048 || key.algorithm.modulusLength > 8192) fail("仅接受 2048–8192 位 RSA 密钥");
  return key;
}
async function passwordKey(password, salt, iterations, bits) {
  if (!text(password)) fail("口令不能为空");
  if (salt.length < 16 || salt.length > 64) fail("盐值必须为 16–64 字节");
  iterations = integer(iterations, 1, 2e6, "迭代次数");
  const base = await subtle().importKey("raw", decodeBytes(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, bits));
}
function parseEnvelope(input) {
  let value;
  try {
    value = JSON.parse(text(input));
  } catch {
    fail("密文包不是有效 JSON；第三方密文请选择「原始密文」");
  }
  if (!value || value.app !== "CipherDesk" || value.v !== 1 || typeof value.algorithm !== "string" || typeof value.ciphertext !== "string") fail("不是 CipherDesk v1 密文包；第三方密文请选择「原始密文」并提供 IV");
  return value;
}
async function aes(job) {
  const encrypt = job.op === "encrypt";
  if (!encrypt && job.op !== "decrypt") fail("AES 操作必须是 encrypt 或 decrypt");
  let mode = job.algorithm ?? "AES-GCM", iv, cipher, key, salt, iterations = job.iterations ?? 6e5, bits = Number(job.bits ?? 256), aad = decodeBytes(job.aad ?? "");
  let keyMode = job.keyMode ?? "raw", envelope;
  if (!encrypt && job.cipherFormat !== "raw") {
    envelope = parseEnvelope(job.input);
    mode = envelope.algorithm;
    iv = decodeBytes(envelope.iv, "base64");
    cipher = decodeBytes(envelope.ciphertext, "base64", MAX_BYTES + 64);
    aad = envelope.aad !== void 0 ? decodeBytes(envelope.aad, "base64") : new Uint8Array();
    if (envelope.kdf) {
      if (envelope.kdf.name !== "PBKDF2-SHA256") fail("不支持的密钥派生方式");
      keyMode = "password";
      salt = decodeBytes(envelope.kdf.salt, "base64");
      iterations = envelope.kdf.iterations;
      bits = envelope.bits;
    } else keyMode = "raw";
  }
  if (!["AES-GCM", "AES-CBC", "AES-CTR"].includes(mode)) fail("不支持的 AES 模式");
  if (envelope && (mode === "AES-GCM" && envelope.tagLength !== 128 || mode === "AES-CTR" && envelope.counterLength !== 64)) fail("密文包的 Tag / counter 位数不受支持");
  if (keyMode === "password") {
    bits = Number(bits);
    if (![128, 192, 256].includes(bits)) fail("AES 位数只能是 128 / 192 / 256");
    if (!salt) salt = encrypt ? randomBytes(16) : decodeBytes(job.salt ?? "", "hex");
    key = await passwordKey(job.password ?? "", salt, iterations, bits);
  } else if (keyMode === "raw") {
    key = decodeBytes(job.key ?? "", job.keyFormat ?? "hex");
    if (![16, 24, 32].includes(key.length)) fail("AES 密钥必须为 16 / 24 / 32 字节，请检查编码");
    bits = key.length * 8;
  } else fail("未知密钥方式");
  if (envelope && Number(envelope.bits) !== bits) fail("密文包的密钥位数与所提供密钥不一致");
  if (encrypt) iv = randomBytes(mode === "AES-GCM" ? 12 : 16);
  else if (!iv) iv = decodeBytes(job.iv ?? "", "hex");
  if (iv.length !== (mode === "AES-GCM" ? 12 : 16)) fail(`${mode} 的 IV 必须为 ${mode === "AES-GCM" ? 12 : 16} 字节`);
  const algorithm = mode === "AES-GCM" ? { name: mode, iv, tagLength: 128, additionalData: aad } : mode === "AES-CTR" ? { name: mode, counter: iv, length: 64 } : { name: mode, iv };
  const cryptoKey = await subtle().importKey("raw", key, mode, false, [encrypt ? "encrypt" : "decrypt"]);
  if (encrypt) {
    cipher = new Uint8Array(await subtle().encrypt(algorithm, cryptoKey, decodeBytes(job.input ?? "", job.inputFormat ?? "utf8")));
    const bundle = { app: "CipherDesk", v: 1, algorithm: mode, bits, iv: encodeBytes(iv), ciphertext: encodeBytes(cipher) };
    if (mode === "AES-GCM") {
      bundle.tagLength = 128;
      if (aad.length) bundle.aad = encodeBytes(aad);
    }
    if (mode === "AES-CTR") bundle.counterLength = 64;
    if (salt) bundle.kdf = { name: "PBKDF2-SHA256", salt: encodeBytes(salt), iterations: Number(iterations) };
    return result(job.cipherFormat === "raw" ? encodeBytes(cipher, job.binaryFormat ?? "base64") : JSON.stringify(bundle, null, 2), { algorithm: mode, bits, iv: toHex(iv), authenticated: mode === "AES-GCM", format: job.cipherFormat === "raw" ? job.binaryFormat ?? "base64" : "CipherDesk JSON（GCM 密文末尾含 16 字节 Tag）" }, { iv: toHex(iv), ...salt ? { salt: toHex(salt) } : {} });
  }
  if (!cipher) cipher = decodeBytes(job.input ?? "", job.binaryFormat ?? "base64", MAX_BYTES + 64);
  if (mode === "AES-GCM" && cipher.length < 16) fail("GCM 密文必须包含末尾 16 字节认证 Tag");
  let plain;
  try {
    plain = new Uint8Array(await subtle().decrypt(algorithm, cryptoKey, cipher));
  } catch {
    fail("解密失败：密钥、IV、AAD、认证 Tag 或密文不匹配");
  }
  limit(plain);
  return result(encodeBytes(plain, job.outputFormat ?? "utf8"), { algorithm: mode, bits, authenticated: mode === "AES-GCM", format: job.outputFormat ?? "utf8" });
}
async function sm4Task(job) {
  const encrypt = job.op === "encrypt";
  if (!encrypt && job.op !== "decrypt") fail("SM4 操作必须是 encrypt 或 decrypt");
  let mode = job.algorithm ?? "SM4-CBC", iv, cipher;
  if (!encrypt && job.cipherFormat !== "raw") {
    const bundle = parseEnvelope(job.input);
    mode = bundle.algorithm;
    cipher = decodeBytes(bundle.ciphertext, "base64", MAX_BYTES + 64);
    if (bundle.iv) iv = decodeBytes(bundle.iv, "base64");
  }
  if (!["SM4-CBC", "SM4-ECB"].includes(mode)) fail("不支持的 SM4 模式");
  const key = decodeBytes(job.key ?? "", job.keyFormat ?? "hex");
  if (key.length !== 16) fail("SM4 密钥必须为 16 字节");
  if (mode === "SM4-CBC") {
    if (encrypt) iv = randomBytes(16);
    else if (!iv) iv = decodeBytes(job.iv ?? "", "hex");
    if (iv.length !== 16) fail("SM4-CBC 的 IV 必须为 16 字节");
  }
  const options = { padding: "none", output: "array", ...mode === "SM4-CBC" ? { mode: "cbc", iv: toHex(iv) } : {} };
  if (encrypt) {
    const input = decodeBytes(job.input ?? "", job.inputFormat ?? "utf8"), padding2 = 16 - input.length % 16, padded2 = new Uint8Array(input.length + padding2);
    padded2.set(input);
    padded2.fill(padding2, input.length);
    cipher = Uint8Array.from(sm4.encrypt(Array.from(padded2), Array.from(key), options));
    const bundle = { app: "CipherDesk", v: 1, algorithm: mode, iv: iv ? encodeBytes(iv) : void 0, ciphertext: encodeBytes(cipher) };
    return result(job.cipherFormat === "raw" ? encodeBytes(cipher, job.binaryFormat ?? "base64") : JSON.stringify(bundle, null, 2), { algorithm: mode, padding: "PKCS#7", authenticated: false, ...iv ? { iv: toHex(iv) } : {} }, iv ? { iv: toHex(iv) } : void 0);
  }
  if (!cipher) cipher = decodeBytes(job.input ?? "", job.binaryFormat ?? "base64", MAX_BYTES + 64);
  if (!cipher.length || cipher.length % 16) fail("SM4 密文长度必须是非零的 16 字节倍数");
  const padded = Uint8Array.from(sm4.decrypt(Array.from(cipher), Array.from(key), options)), padding = padded.at(-1);
  if (!padding || padding > 16 || !padded.subarray(padded.length - padding).every((x) => x === padding)) fail("SM4 解密失败：密钥、IV、密文或 PKCS#7 填充不匹配");
  return result(encodeBytes(limit(padded.subarray(0, -padding)), job.outputFormat ?? "utf8"), { algorithm: mode, authenticated: false, format: job.outputFormat ?? "utf8" });
}
async function rsa(job) {
  if (job.op === "generate") {
    const bits = Number(job.bits ?? 2048);
    if (![2048, 3072, 4096].includes(bits)) fail("RSA 位数只能是 2048 / 3072 / 4096");
    const keys = await subtle().generateKey({ name: "RSA-OAEP", modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
    const publicKey = pem(new Uint8Array(await subtle().exportKey("spki", keys.publicKey)), "PUBLIC KEY"), privateKey = pem(new Uint8Array(await subtle().exportKey("pkcs8", keys.privateKey)), "PRIVATE KEY");
    return result("RSA 密钥对已生成；公钥和私钥已填入对应区域。", { bits, publicFormat: "SPKI", privateFormat: "PKCS#8（未加密）" }, { publicKey, privateKey });
  }
  if (["encrypt", "decrypt"].includes(job.op)) {
    const encrypt = job.op === "encrypt", key2 = await rsaKey(encrypt ? job.publicKey : job.privateKey, !encrypt), input2 = decodeBytes(job.input ?? "", encrypt ? job.inputFormat ?? "utf8" : job.binaryFormat ?? "base64");
    const max = key2.algorithm.modulusLength / 8 - 66;
    if (encrypt && input2.length > max) fail(`RSA-OAEP / SHA-256 最多加密 ${max} 字节；长文本请用 AES`);
    let bytes;
    try {
      bytes = new Uint8Array(await subtle()[encrypt ? "encrypt" : "decrypt"]({ name: "RSA-OAEP" }, key2, input2));
    } catch {
      fail("RSA 解密失败：请检查密钥、密文、OAEP 与 SHA-256 参数");
    }
    return result(encodeBytes(bytes, encrypt ? job.binaryFormat ?? "base64" : job.outputFormat ?? "utf8"), { algorithm: "RSA-OAEP / SHA-256", bits: key2.algorithm.modulusLength });
  }
  if (!["sign", "verify"].includes(job.op)) fail("未知 RSA 操作");
  const name = job.algorithm ?? "RSA-PSS";
  if (!["RSA-PSS", "RSASSA-PKCS1-v1_5"].includes(name)) fail("未知 RSA 签名算法");
  const verify = job.op === "verify", key = await rsaKey(verify ? job.publicKey : job.privateKey, !verify, name), algorithm = name === "RSA-PSS" ? { name, saltLength: 32 } : { name }, input = decodeBytes(job.input ?? "", job.inputFormat ?? "utf8");
  if (!verify) return result(encodeBytes(new Uint8Array(await subtle().sign(algorithm, key, input)), job.binaryFormat ?? "base64"), { algorithm: name, hash: "SHA-256", ...name === "RSA-PSS" ? { saltLength: 32 } : {} });
  const valid = await subtle().verify(algorithm, key, decodeBytes(job.signature ?? "", job.binaryFormat ?? "base64"), input);
  return result(valid ? "签名匹配" : "签名不匹配", { algorithm: name, verified: valid });
}
async function jwt(job) {
  const token = text(job.input ?? "").trim();
  if (token.length > 65536) fail("JWT 最多 64 KiB");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((x) => !x)) fail("需要三段式 JWS / JWT，不支持 JWE 或空签名");
  let headerText, payloadText, header, payload;
  try {
    headerText = encodeBytes(decodeBytes(parts[0], "base64url"), "utf8");
    payloadText = encodeBytes(decodeBytes(parts[1], "base64url"), "utf8");
    header = JSON.parse(headerText);
    payload = JSON.parse(payloadText);
  } catch {
    fail("JWT Header / Payload 必须为有效 UTF-8 JSON");
  }
  if (!header || typeof header !== "object" || Array.isArray(header) || !payload || typeof payload !== "object" || Array.isArray(payload)) fail("JWT Header 和 Payload 必须是 JSON 对象");
  const details = { algorithm: typeof header.alg === "string" ? header.alg : "缺失", signature: "未验证；解码不等于可信", claims: "未校验 issuer / audience / nonce 等业务声明" };
  const now = Date.now() / 1e3;
  if (Number.isFinite(payload.exp)) details.exp = payload.exp <= now ? "已过期" : "尚未过期";
  if (Number.isFinite(payload.nbf)) details.nbf = payload.nbf > now ? "尚未生效" : "已到生效时间";
  if (job.op === "verify") {
    if (!["HS256", "RS256"].includes(job.algorithm) || header.alg !== job.algorithm) fail("JWT alg 与所选验签算法不一致（仅支持 HS256 / RS256）");
    if (header.crit !== void 0 || header.b64 !== void 0) fail("暂不支持 crit / b64 扩展头");
    const data = encoder.encode(parts[0] + "." + parts[1]), signature = decodeBytes(parts[2], "base64url");
    let valid;
    if (job.algorithm === "HS256") {
      const raw = decodeBytes(job.key ?? "", job.keyFormat ?? "utf8");
      if (raw.length < 32) fail("HS256 密钥至少需要 32 字节");
      const key = await subtle().importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
      valid = await subtle().verify("HMAC", key, signature, data);
    } else valid = await subtle().verify("RSASSA-PKCS1-v1_5", await rsaKey(job.publicKey, false, "RSASSA-PKCS1-v1_5"), signature, data);
    details.verified = valid;
    details.signature = valid ? "签名匹配；仍须校验业务声明" : "签名不匹配";
  } else if (job.op !== "decode") fail("JWT 操作必须为 decode 或 verify");
  return result(`HEADER（原始 JSON）
${headerText}

PAYLOAD（原始 JSON）
${payloadText}`, details);
}
export async function runTask(job) {
  if (!job || typeof job !== "object" || Array.isArray(job)) fail("任务必须为 JSON 对象");
  for (const value of Object.values(job)) if (typeof value === "string") text(value);
  if (job.tool === "codec") {
    if (job.algorithm !== void 0 && !["bytes", "url"].includes(job.algorithm)) fail("未知编码转换类型");
    if (job.algorithm === "url") {
      try {
        return result(job.op === "encode" ? encodeURIComponent(text(job.input ?? "")) : job.op === "decode" ? decodeURIComponent(text(job.input ?? "")) : fail("未知 URL 操作"), { note: "URL component 编码，不是加密" });
      } catch {
        fail("URL component 编码无效，请检查百分号或 Unicode");
      }
    }
    return result(encodeBytes(decodeBytes(job.input ?? "", job.inputFormat ?? "utf8"), job.outputFormat ?? "base64"), { note: "可逆编码转换，不提供加密保护" });
  }
  if (job.tool === "hash") {
    const input = decodeBytes(job.input ?? "", job.inputFormat ?? "utf8"), name = job.algorithm ?? "SHA-256";
    let bytes;
    if (name === "MD5") bytes = md5(input);
    else if (name === "SM3") bytes = decodeBytes(sm3(Array.from(input)), "hex");
    else if (name === "SHA3-256") bytes = sha3_256(input);
    else if (name === "SHA3-512") bytes = sha3_512(input);
    else bytes = new Uint8Array(await subtle().digest(hashName(name), input));
    return result(encodeBytes(bytes, job.binaryFormat ?? "hex"), { algorithm: name, bytes: input.length, reversible: false, ...["MD5", "SHA-1"].includes(name) ? { note: "旧系统校验兼容用途，不用于新签名或密码存储" } : { note: "摘要不可解密；快速哈希不适合直接存储登录密码" } });
  }
  if (job.tool === "hmac") {
    const keyBytes = decodeBytes(job.key ?? "", job.keyFormat ?? "utf8");
    if (!keyBytes.length) fail("HMAC 密钥不能为空");
    const name = hashName(job.algorithm ?? "SHA-256"), verify = job.op === "verify";
    if (!verify && job.op !== "sign") fail("HMAC 操作必须为 sign 或 verify");
    const key = await subtle().importKey("raw", keyBytes, { name: "HMAC", hash: name }, false, [verify ? "verify" : "sign"]), input = decodeBytes(job.input ?? "", job.inputFormat ?? "utf8");
    if (verify) {
      const valid = await subtle().verify("HMAC", key, decodeBytes(job.signature ?? "", job.binaryFormat ?? "hex"), input);
      return result(valid ? "MAC 匹配" : "MAC 不匹配", { algorithm: "HMAC-" + name, verified: valid });
    }
    return result(encodeBytes(new Uint8Array(await subtle().sign("HMAC", key, input)), job.binaryFormat ?? "hex"), { algorithm: "HMAC-" + name });
  }
  if (job.tool === "aes") return aes(job);
  if (job.tool === "sm4") return sm4Task(job);
  if (job.tool === "rsa") return rsa(job);
  if (job.tool === "jwt") return jwt(job);
  if (job.tool === "kdf") {
    const salt = decodeBytes(job.salt ?? "", "hex"), iterations = integer(job.iterations ?? 6e5, 1, 2e6, "迭代次数"), bytes = integer(job.bytes ?? 32, 16, 64, "派生字节数");
    const derived = await passwordKey(job.input ?? "", salt, iterations, bytes * 8);
    return result(encodeBytes(derived, job.binaryFormat ?? "hex"), { algorithm: "PBKDF2-HMAC-SHA256", iterations, bytes, salt: toHex(salt), note: "保存盐和迭代次数才能再次得到相同结果；不能解密" });
  }
  if (job.tool === "random") {
    if (job.algorithm !== void 0 && !["bytes", "uuid"].includes(job.algorithm)) fail("未知随机值类型");
    if (job.algorithm === "uuid") return result(crypto.randomUUID(), { algorithm: "UUID v4" });
    const bytes = integer(job.bytes ?? 32, 1, 4096, "随机字节数");
    return result(encodeBytes(randomBytes(bytes), job.binaryFormat ?? "hex"), { algorithm: "crypto.getRandomValues", bytes });
  }
  fail("未知工具：请选择 codec / hash / hmac / aes / sm4 / rsa / jwt / kdf / random");
}
