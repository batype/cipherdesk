const $ = (id) => document.getElementById(id);
const catalog = [
  { id: "aes", icon: "⌑", title: "AES 加解密", sub: "SYMMETRIC", desc: "用同一把密钥加密和解密。默认 GCM，为密文加上完整性校验。", badge: "AES · 128 / 192 / 256", ops: [["encrypt", "加密"], ["decrypt", "解密"]], action: { encrypt: "开始加密", decrypt: "开始解密" }, group: "加密与签名" },
  { id: "rsa", icon: "⚿", title: "RSA 密钥与签名", sub: "ASYMMETRIC", desc: "公钥加密、私钥解密；也可生成密钥对，或进行签名验签。", badge: "WEB CRYPTO", ops: [["encrypt", "加密"], ["decrypt", "解密"], ["sign", "签名"], ["verify", "验签"], ["generate", "生成密钥"]], action: { generate: "生成密钥对" }, group: null },
  { id: "sm4", icon: "国", title: "国密 SM4", sub: "CHINESE STANDARD", desc: "SM4 128 位分组加密。支持 CBC 与用于旧系统对接的 ECB。", badge: "SM4 · 128", ops: [["encrypt", "加密"], ["decrypt", "解密"]] },
  { id: "hash", icon: "#", title: "哈希摘要", sub: "HASH DIGEST", desc: "快速生成摘要，检查内容是否一致。支持 SHA 系列、SM3 与 MD5。", badge: "ONE WAY", ops: [["digest", "生成摘要"]], group: "校验与解析" },
  { id: "hmac", icon: "≋", title: "HMAC 消息认证", sub: "MESSAGE AUTH", desc: "用共享密钥生成或验证消息认证码，校验消息完整性。", badge: "SHARED KEY", ops: [["sign", "生成 MAC"], ["verify", "验证 MAC"]] },
  { id: "jwt", icon: "{·}", title: "JWT 解析与验签", sub: "TOKEN INSPECTOR", desc: "查看 Header 与 Payload，并选择 HS256 / RS256 验证签名。", badge: "JWS · JWT", ops: [["decode", "解析"], ["verify", "验证签名"]] },
  { id: "codec", icon: "↔", title: "编码转换", sub: "TEXT & BYTES", desc: "在 UTF-8、Hex、Base64、Base64URL 之间转换，或处理 URL 编码。", badge: "REVERSIBLE", ops: [["convert", "转换"]], group: "数据与密钥" },
  { id: "kdf", icon: "⊞", title: "PBKDF2 密钥派生", sub: "KEY DERIVATION", desc: "将口令与盐值派生为密钥。重复使用相同参数可得到相同结果。", badge: "PBKDF2 · SHA-256", ops: [["derive", "派生密钥"]] },
  { id: "random", icon: "✳", title: "安全随机值", sub: "RANDOM GENERATOR", desc: "生成随机字节或 UUID v4，用于密钥、盐值和开发测试。", badge: "CRYPTO RANDOM", ops: [["generate", "生成随机值"]] }
];
let current = catalog[0], op = "encrypt", state = {}, worker, serial = 0, busy = false, hasResult = false;
const formatOptions = [["utf8", "UTF-8 文本"], ["hex", "Hex"], ["base64", "Base64"], ["base64url", "Base64URL"]];
const binaryOptions = formatOptions.slice(1);
const defaults = { aes: { algorithm: "AES-GCM", keyMode: "raw", bits: "256", keyFormat: "hex", cipherFormat: "envelope", binaryFormat: "base64", inputFormat: "utf8", outputFormat: "utf8", iterations: "600000" }, rsa: { algorithm: "RSA-PSS", bits: "2048", inputFormat: "utf8", outputFormat: "utf8", binaryFormat: "base64" }, sm4: { algorithm: "SM4-CBC", keyFormat: "hex", cipherFormat: "envelope", binaryFormat: "base64", inputFormat: "utf8", outputFormat: "utf8" }, hash: { algorithm: "SHA-256", inputFormat: "utf8", binaryFormat: "hex" }, hmac: { algorithm: "SHA-256", keyFormat: "utf8", inputFormat: "utf8", binaryFormat: "hex" }, jwt: { algorithm: "HS256", keyFormat: "utf8" }, codec: { algorithm: "bytes", inputFormat: "utf8", outputFormat: "base64", urlOp: "encode" }, kdf: { bytes: "32", iterations: "600000", binaryFormat: "hex" }, random: { algorithm: "bytes", bytes: "32", binaryFormat: "hex" } };
const notes = { aes: "GCM 推荐用于新数据。每次加密自动生成新 IV；原始 GCM 密文末尾包含 16 字节 Tag。CBC / CTR 不校验完整性。", rsa: "RSA-OAEP 使用 SHA-256：2048 位密钥最多加密 190 字节。公钥需 SPKI，私钥需未加密 PKCS#8 PEM。", sm4: "CBC / ECB 均不校验密文完整性；ECB 仅用于兼容。填充固定为 PKCS#7。SM3 摘要请进入「哈希摘要」。", hash: "摘要不可逆，不存在通用“解密”。MD5 / SHA-1 仅用于旧系统兼容；快速哈希不适合直接存储登录密码。", hmac: "HMAC 是认证码，不是可逆加密。验签会检查输入内容、密钥与 MAC 是否匹配。", jwt: "解析不等于可信。签名匹配后仍需校验 issuer、audience 等业务声明；这里的 exp / nbf 提示不代表完成鉴权。", codec: "编码不是加密，不需要密钥。URL 使用 encodeURIComponent / decodeURIComponent，不将 + 当空格。", kdf: "默认 600,000 次迭代。为兼容测试允许更低值；实际使用需评估口令强度与运行成本。请保存盐值与迭代次数。", random: "通过系统密码学随机源生成。随机密钥和 UUID 都不保存到浏览器历史记录。" };
function newWorker() {
  worker?.terminate();
  worker = new Worker("./worker.bundle.mjs", { type: "module" });
  worker.onmessage = ({ data }) => {
    if (data.id !== serial) return;
    setBusy(false);
    if (data.error) {
      invalidate();
      message(data.error, true);
      return;
    }
    const { output, details, params } = data.result;
    $("output").value = output;
    hasResult = true;
    for (const id of ["copy", "download", "reuse"]) $(id).disabled = false;
    $("result-status").textContent = details.verified === true ? "验证匹配" : details.verified === false ? "验证不匹配" : "处理完成";
    $("result-details").replaceChildren();
    for (const [key, value] of Object.entries(details)) {
      const item = document.createElement("div"), dt = document.createElement("dt"), dd = document.createElement("dd");
      dt.textContent = { algorithm: "算法", bits: "密钥位数", bytes: "字节数", iv: "IV / Counter · Hex", authenticated: "含认证校验", format: "输出格式", verified: "签名 / MAC 验证", signature: "签名状态", claims: "业务声明", reversible: "可逆", note: "提示", padding: "填充", iterations: "迭代次数", salt: "盐值 · Hex", hash: "摘要", saltLength: "PSS 盐长度", publicFormat: "公钥格式", privateFormat: "私钥格式", exp: "过期时间", nbf: "生效时间" }[key] ?? key;
      dd.textContent = typeof value === "boolean" ? value ? "是" : "否" : String(value);
      item.append(dt, dd);
      $("result-details").append(item);
    }
    if (params) {
      Object.assign(state, params);
      renderFields();
    }
    if (!(current.id === "rsa" && op === "generate")) $("parameters").open = false;
    message(details.verified === false ? "内容或签名不匹配，请检查输入和密钥。" : current.id === "rsa" && op === "generate" ? "密钥已填入参数区。私钥仅在当前页面内存中，请按需导出保存。" : "已在本地完成处理。");
  };
  worker.onerror = () => {
    if (busy) {
      setBusy(false);
      invalidate();
      message("处理线程发生错误，请刷新页面重试。", true);
    }
  };
}
function setBusy(value) {
  busy = value;
  $("run").disabled = value;
  for (const id of ["sample", "tools", "operations", "fields"]) $(id).inert = value;
  $("input").readOnly = value;
  $("file").disabled = value;
  updateAction();
  if (value) {
    $("result-status").textContent = "正在处理…";
    message("正在本地计算…");
  }
}
function message(value, error = false) {
  $("message").textContent = value;
  $("message").classList.toggle("error", error);
}
function invalidate() {
  hasResult = false;
  $("output").value = "";
  $("result-details").replaceChildren();
  $("result-status").textContent = "等待处理";
  for (const id of ["copy", "download", "reuse"]) $(id).disabled = true;
}
function makeField(id, label, { options, value, secret = false, wide = false, full = false, multi = false, hint, button, number = false } = {}) {
  const wrap = document.createElement("div");
  wrap.className = "field" + (wide ? " wide" : "") + (full ? " full" : "");
  const lab = document.createElement("label");
  lab.htmlFor = "f-" + id;
  lab.textContent = label;
  wrap.append(lab);
  let field;
  if (options) {
    field = document.createElement("select");
    for (const entry of options) {
      const [v, t] = Array.isArray(entry) ? entry : [entry, entry];
      const option = document.createElement("option");
      option.value = v;
      option.textContent = t;
      field.append(option);
    }
  } else {
    field = document.createElement(multi ? "textarea" : "input");
    if (!multi) field.type = secret ? "password" : number ? "number" : "text";
    field.autocomplete = "off";
    field.spellcheck = false;
    field.setAttribute("autocapitalize", "off");
    if (secret) {
      field.setAttribute("data-secret", "true");
      field.setAttribute("aria-label", label);
    }
    if (multi) field.rows = 4;
  }
  field.id = "f-" + id;
  field.value = state[id] ?? value ?? "";
  field.addEventListener(options ? "change" : "input", () => {
    state[id] = field.value;
    invalidate();
    message("");
    if (options) {
      renderFields();
      updateAction();
    }
  });
  if (button || secret && !multi) {
    const row = document.createElement("div");
    row.className = "field-row";
    row.append(field);
    if (secret && !multi) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = "显示";
      b.setAttribute("aria-label", "显示或隐藏" + label);
      b.onclick = () => {
        field.type = field.type === "password" ? "text" : "password";
        b.textContent = field.type === "password" ? "显示" : "隐藏";
      };
      row.append(b);
    }
    if (button) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = button.label;
      b.onclick = button.run;
      row.append(b);
    }
    wrap.append(row);
  } else wrap.append(field);
  if (multi && ["publicKey", "privateKey"].includes(id)) {
    const save = document.createElement("button");
    save.type = "button";
    save.textContent = id === "privateKey" ? "下载私钥 PEM" : "下载公钥 PEM";
    save.onclick = () => {
      if (!field.value) {
        message("请先生成或填入密钥。", true);
        return;
      }
      const url = URL.createObjectURL(new Blob([field.value], { type: "text/plain" })), a = document.createElement("a");
      a.href = url;
      a.download = id === "privateKey" ? "cipherdesk-private-key.pem" : "cipherdesk-public-key.pem";
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1e3);
    };
    wrap.append(save);
  }
  if (hint) {
    const small = document.createElement("small");
    small.textContent = hint;
    wrap.append(small);
  }
  $("fields").append(wrap);
}
const select = (id, label, options, extra = {}) => makeField(id, label, { options, ...extra });
function generateHex(bytes) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (n) => n.toString(16).padStart(2, "0")).join("");
}
function keyField() {
  makeField("key", "密钥", { secret: true, wide: true, button: ["aes", "sm4"].includes(current.id) ? { label: "生成密钥", run: () => {
    state.keyFormat = "hex";
    state.key = generateHex(current.id === "sm4" ? 16 : Number(state.bits) / 8);
    invalidate();
    renderFields();
    message("新密钥已生成，仅保存在当前页面。");
  } } : void 0 });
  select("keyFormat", "密钥编码", formatOptions);
}
function renderFields() {
  $("fields").replaceChildren();
  const t = current.id, s = state;
  if (["aes", "sm4"].includes(t)) {
    select("algorithm", "算法 / 模式", t === "aes" ? [["AES-GCM", "AES-GCM · 推荐"], ["AES-CBC", "AES-CBC · 兼容"], ["AES-CTR", "AES-CTR · 兼容"]] : [["SM4-CBC", "SM4-CBC"], ["SM4-ECB", "SM4-ECB · 仅兼容"]]);
    select("cipherFormat", "密文格式", [["envelope", "CipherDesk JSON 密文包"], ["raw", "原始密文 · 对接第三方"]]);
    if (t === "aes") {
      select("keyMode", "密钥方式", [["raw", "原始密钥"], ["password", "口令派生 · PBKDF2"]]);
      select("bits", "生成 / 派生密钥位数", ["128", "192", "256"]);
    }
    if (t === "sm4" || s.keyMode === "raw") keyField();
    else {
      makeField("password", "口令", { secret: true, wide: true });
      makeField("iterations", "PBKDF2 迭代次数", { number: true, hint: "默认 600000；密文包解密时自动读取" });
    }
    if (s.cipherFormat === "raw") {
      select("binaryFormat", "密文编码", binaryOptions);
      if (op === "decrypt" && s.algorithm !== "SM4-ECB") makeField("iv", "IV / Counter · Hex", { wide: true, hint: t === "aes" && s.algorithm === "AES-GCM" ? "12 字节，24 个 Hex 字符" : "16 字节，32 个 Hex 字符" });
      if (t === "aes" && s.keyMode === "password" && op === "decrypt") makeField("salt", "PBKDF2 盐值 · Hex", { wide: true });
    }
    if (t === "aes" && s.algorithm === "AES-GCM") makeField("aad", "AAD · UTF-8，可选", { wide: true, hint: "附加认证数据；密文包解密时优先读取包内 AAD" });
    if (op === "encrypt") select("inputFormat", "明文输入编码", formatOptions);
    else select("outputFormat", "解密输出编码", formatOptions);
    if (op === "decrypt" && s.cipherFormat === "envelope") {
      const note = document.createElement("small");
      note.textContent = "密文包会自动读取模式、IV、AAD 和派生参数；请提供对应密钥或口令。";
      $("fields").append(note);
    }
  } else if (t === "rsa") {
    if (op === "generate") select("bits", "密钥位数", ["2048", "3072", "4096"]);
    if (["sign", "verify"].includes(op)) select("algorithm", "签名算法", [["RSA-PSS", "RSA-PSS / SHA-256 · salt 32"], ["RSASSA-PKCS1-v1_5", "PKCS#1 v1.5 / SHA-256"]]);
    if (op !== "generate") {
      select("binaryFormat", "密文 / 签名编码", binaryOptions);
      select(op === "decrypt" ? "outputFormat" : "inputFormat", op === "decrypt" ? "明文输出编码" : "内容输入编码", formatOptions);
    }
    if (["generate", "encrypt", "verify"].includes(op)) makeField("publicKey", "公钥 · SPKI PEM", { multi: true, full: true });
    if (["generate", "decrypt", "sign"].includes(op)) makeField("privateKey", "私钥 · PKCS#8 PEM", { multi: true, full: true, hint: "未加密私钥，仅在当前页面内存中保留；清空全部可移除。" });
    if (op === "verify") makeField("signature", "待验证签名", { multi: true, full: true });
  } else if (t === "hash") {
    select("algorithm", "摘要算法", ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512", "SM3", ["MD5", "MD5 · 仅兼容"], ["SHA-1", "SHA-1 · 仅兼容"]]);
    select("inputFormat", "输入编码", formatOptions);
    select("binaryFormat", "摘要输出编码", binaryOptions);
  } else if (t === "hmac") {
    select("algorithm", "HMAC 摘要", ["SHA-256", "SHA-384", "SHA-512", ["SHA-1", "SHA-1 · 仅兼容"]]);
    select("inputFormat", "内容输入编码", formatOptions);
    select("binaryFormat", "MAC 编码", binaryOptions);
    keyField();
    if (op === "verify") makeField("signature", "待验证 MAC", { multi: true, full: true });
  } else if (t === "jwt") {
    if (op === "verify") {
      select("algorithm", "预期签名算法", ["HS256", "RS256"]);
      if (s.algorithm === "HS256") {
        keyField();
      } else makeField("publicKey", "公钥 · SPKI PEM", { multi: true, full: true });
    } else {
      const p = document.createElement("small");
      p.textContent = "无需密钥即可解析 JWT；只有验证签名才能检查签名是否匹配。";
      $("fields").append(p);
    }
  } else if (t === "codec") {
    select("algorithm", "转换类型", [["bytes", "字节编码转换"], ["url", "URL component"]]);
    if (s.algorithm === "bytes") {
      select("inputFormat", "输入编码", formatOptions);
      select("outputFormat", "输出编码", formatOptions);
    } else select("urlOp", "操作", [["encode", "编码 · encode"], ["decode", "解码 · decode"]]);
  } else if (t === "kdf") {
    makeField("salt", "盐值 · Hex", { wide: true, button: { label: "生成盐值", run: () => {
      state.salt = generateHex(16);
      invalidate();
      renderFields();
    } } });
    makeField("iterations", "迭代次数", { number: true });
    makeField("bytes", "派生字节数 · 16–64", { number: true });
    select("binaryFormat", "输出编码", binaryOptions);
  } else if (t === "random") {
    select("algorithm", "随机值类型", [["bytes", "密码学随机字节"], ["uuid", "UUID v4"]]);
    if (s.algorithm === "bytes") {
      makeField("bytes", "随机字节数 · 1–4096", { number: true });
      select("binaryFormat", "输出编码", binaryOptions);
    }
  }
  $("parameter-summary").textContent = s.algorithm ?? (t === "kdf" ? "PBKDF2-SHA256" : "");
  $("context-note").textContent = notes[t];
  $("input-label").textContent = t === "kdf" ? "口令输入" : t === "jwt" ? "JWT Token" : t === "random" ? "无需输入" : op === "generate" ? "无需输入" : op === "decrypt" ? "密文输入" : "输入内容";
  $("input").disabled = t === "random" || t === "rsa" && op === "generate";
}
function updateAction() {
  const labels = { encrypt: "开始加密", decrypt: "开始解密", sign: "生成签名", verify: "开始验证", digest: "生成摘要", decode: "解析 JWT", convert: "开始转换", derive: "派生密钥", generate: "生成随机值" };
  $("run").replaceChildren(document.createTextNode(busy ? "正在处理…" : current.action?.[op] ?? labels[op]));
  const span = document.createElement("span");
  span.textContent = busy ? "…" : "↗";
  $("run").append(span);
}
function renderOperations() {
  $("operations").replaceChildren();
  for (const [value, label] of current.ops) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.classList.toggle("active", op === value);
    b.setAttribute("aria-pressed", String(op === value));
    b.onclick = () => {
      op = value;
      invalidate();
      message("");
      renderOperations();
      renderFields();
      updateAction();
    };
    $("operations").append(b);
  }
}
function activate(id) {
  serial++;
  newWorker();
  setBusy(false);
  current = catalog.find((t) => t.id === id) ?? catalog[0];
  op = current.ops[0][0];
  state = { ...defaults[current.id] };
  $("input").value = "";
  invalidate();
  message("");
  document.querySelectorAll(".nav-tool").forEach((b) => {
    b.classList.toggle("active", b.dataset.tool === current.id);
    b.setAttribute("aria-current", b.dataset.tool === current.id ? "page" : "false");
  });
  $("tool-title").textContent = current.title;
  $("tool-desc").textContent = current.desc;
  $("tool-code").textContent = current.id.toUpperCase();
  $("tool-badge").textContent = current.badge;
  renderOperations();
  renderFields();
  updateAction();
  count();
  history.replaceState(null, "", "#" + current.id);
}
for (const t of catalog) {
  if (t.group) {
    const p = document.createElement("p");
    p.className = "nav-group";
    p.textContent = t.group;
    $("tools").append(p);
  }
  const b = document.createElement("button");
  b.type = "button";
  b.className = "nav-tool";
  b.dataset.tool = t.id;
  const icon = document.createElement("span");
  icon.className = "nav-icon";
  icon.textContent = t.icon;
  icon.setAttribute("aria-hidden", "true");
  const text = document.createElement("span"), strong = document.createElement("strong"), small = document.createElement("small");
  strong.textContent = t.title;
  small.textContent = t.sub;
  text.append(strong, small);
  b.append(icon, text);
  b.onclick = () => activate(t.id);
  $("tools").append(b);
}
function count() {
  $("input-count").textContent = new TextEncoder().encode($("input").value).length.toLocaleString() + " B";
}
$("input").addEventListener("input", () => {
  invalidate();
  message("");
  count();
});
$("run").onclick = () => {
  if (busy) return;
  invalidate();
  const job = { ...state, tool: current.id, op: current.id === "codec" && state.algorithm === "url" ? state.urlOp : op, input: $("input").value };
  serial++;
  setBusy(true);
  worker.postMessage({ id: serial, job });
};
$("clear").onclick = () => {
  activate(current.id);
  message("内容、密钥、参数与结果已从页面清空。");
};
$("sample").onclick = () => {
  $("parameters").open = true;
  state = { ...defaults[current.id] };
  let input = "Hello, CipherDesk! 你好，开发者。";
  if (["aes", "sm4"].includes(current.id)) state.key = generateHex(current.id === "sm4" ? 16 : 32);
  if (current.id === "hmac") state.key = "demo-key-for-local-testing-only";
  if (current.id === "kdf") {
    input = "example-password-only";
    state.salt = generateHex(16);
  }
  if (current.id === "jwt") {
    input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vIiwicm9sZSI6ImRldmVsb3BlciJ9.ZGVtby1zaWduYXR1cmU";
    op = "decode";
  } else op = current.ops[0][0];
  if (current.id === "rsa") {
    op = "generate";
    input = "";
  }
  if (current.id === "random") input = "";
  $("input").value = input;
  invalidate();
  renderOperations();
  renderFields();
  updateAction();
  count();
  message("已载入虚构示例。点击主按钮开始处理。");
};
$("reuse").onclick = () => {
  if (!hasResult) return;
  const value = $("output").value;
  if (["aes", "sm4", "rsa"].includes(current.id) && op === "encrypt") op = "decrypt";
  else if (["aes", "sm4", "rsa"].includes(current.id) && op === "decrypt") op = "encrypt";
  $("input").value = value;
  invalidate();
  message("结果已放入输入区。");
  renderOperations();
  renderFields();
  updateAction();
  count();
};
$("copy").onclick = async () => {
  try {
    await navigator.clipboard.writeText($("output").value);
    message("结果已复制到剪贴板。");
  } catch {
    message("无法访问剪贴板，请选中结果手动复制。", true);
  }
};
$("download").onclick = () => {
  if (!hasResult) return;
  const url = URL.createObjectURL(new Blob([$("output").value], { type: "text/plain;charset=utf-8" })), a = document.createElement("a");
  a.href = url;
  a.download = "cipherdesk-" + current.id + "-result.txt";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1e3);
};
$("file").onchange = async () => {
  const file = $("file").files[0];
  $("file").value = "";
  if (!file) return;
  if (file.size > 3 * 1024 * 1024) {
    message("文件最多 3 MiB。", true);
    return;
  }
  try {
    const requestId = serial, buffer = await file.arrayBuffer();
    if (requestId !== serial) return;
    $("input").value = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    invalidate();
    count();
    message("文件已读入当前页面。");
  } catch {
    message("文件不是有效 UTF-8 文本，请转换成 Hex / Base64 后输入。", true);
  }
};
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && !busy) {
    e.preventDefault();
    $("run").click();
  }
});
activate(location.hash.slice(1));
