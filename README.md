# CipherDesk · 开发者密码工具箱

让密文，清楚可控。浏览器本地完成常用加解密、签名校验、编码转换和 JWT 检查；同一套核心也可通过 Node.js API / CLI 使用。

[在线使用](https://batype.github.io/cipherdesk/) · [需求与边界](docs/product.md) · [API 参数](docs/api.md) · [AI Skill](skills/cipherdesk/SKILL.md)

![CipherDesk 亮色界面](https://raw.githubusercontent.com/batype/cipherdesk/main/docs/preview-light.png)

## 能做什么

| 工具 | 首版支持 | 约定 |
|---|---|---|
| AES | GCM、CBC、CTR；128 / 192 / 256 位 | 默认 GCM；每次加密生成新 IV |
| RSA | OAEP 加解密、PSS / PKCS#1 v1.5 签名与验签、生成密钥对 | SHA-256；SPKI 公钥 / 未加密 PKCS#8 私钥 |
| 国密 | SM3 摘要、SM4 CBC / ECB | SM4 为 128 位，PKCS#7 填充 |
| 摘要 | MD5、SHA-1、SHA-256/384/512、SHA3-256/512 | 不可逆；MD5 / SHA-1 仅兼容 |
| HMAC | SHA-1/256/384/512 生成和验证 | 使用共享密钥；不提供解密 |
| JWT | 三段式 JWT 解析、HS256 / RS256 验签 | 解码不代表可信；不代替业务鉴权 |
| 编码 | UTF-8、Hex、Base64、Base64URL、URL component | 编码不提供加密保护 |
| 派生 | PBKDF2-HMAC-SHA256 | 默认 600,000 次；随机盐 |
| 随机 | 安全随机字节、UUID v4 | 使用系统密码学随机源 |

支持亮色 / 暗色 / 跟随系统、手机布局、文本导入、复制、下载，以及结果转输入。工具链接如 `/#jwt` 可以直达对应面板。

## 数据处理与兼容边界

- 网页运算在本地 Worker 中完成，无分析脚本、CDN 或远程处理接口。输入、密钥、口令和结果只留在当前页面内存；只记住主题偏好。刷新、切换工具或“清空全部”会移除页面内容，不承诺物理内存安全擦除。复制、下载由你主动触发。
- 浏览器需 HTTPS / localhost 和现代 Web Crypto 支持。网页可本地托管，不能双击 `file://` 使用 Worker。
- 通常每项解码后的输入最多 1 MiB（密文允许必要的认证 / 填充开销），每个文本字段最多 3 MiB。JWT 最多 64 KiB。不是大文件加密器。
- 默认 CipherDesk v1 JSON 密文包记录算法、IV、位数、AAD、派生盐与迭代次数，**不含密钥或口令**。这不是通用密文标准；第三方密文请选择原始模式，明确提供参数。
- GCM 固定 12 字节 IV、128 位 Tag，Tag 附于密文末尾。CTR 使用 16 字节 counter、64 位计数段。CBC 使用 PKCS#7。原始模式 IV / 盐以 Hex 输入。
- CBC / CTR / SM4 CBC 不提供认证；SM4 ECB 仅兼容旧系统。PKCS#7 校验成功不等于内容真实。新数据优先 AES-GCM。
- RSA 生成 2048 / 3072 / 4096 位，导入接受 2048–8192 位。OAEP SHA-256 的 2048 位密钥最多加密 190 字节。PSS 盐长度固定 32 字节。不处理加密私钥、PKCS#1 PEM、证书、JWE、SM2、DES / 3DES / RC4 或密码破解。
- JWT 只检查显式选择的 HS256 / RS256 签名；不支持 `crit` / `b64` 扩展头。过期 / 生效时间只是提示；issuer、audience、nonce 等需由业务验证。原始 JSON 数字文本保留。
- 工具用于开发调试；尚未经过独立密码学安全审计。

## 本地开发

Node.js 22.14+：

```sh
git clone https://github.com/batype/cipherdesk.git
cd cipherdesk
npm ci
npm test
npm run build
npm run dev
# http://127.0.0.1:4181/
```

构建使用 esbuild 打包本地算法库，网页仅加载同源静态资源。推送 main 后 GitHub Actions 安装依赖、测试、构建并自动部署 Pages。首次部署需在仓库 Settings → Pages 选择 GitHub Actions。

## Node API / CLI

npm 发布需完成官方登录验证，当前先使用源码或 Release 安装。安装来源以 [Releases](https://github.com/batype/cipherdesk/releases) 和 npm 官方公开状态为准。仓库内可直接执行：

```sh
node bin/cipherdesk.mjs --in request.json --out result.json
# 不指定 --in 时从 stdin 读取；不指定 --out 时写 stdout
```

请求文件示例（不将密钥作为命令行参数）：

```json
{"tool":"hash","algorithm":"SHA-256","input":"abc"}
```

Node ESM：

```js
import {runTask} from '@batype/cipherdesk';
const {output} = await runTask({tool:'hash', algorithm:'SM3', input:'abc'});
console.log(output);
```

所有操作共用异步 `runTask(job)`，返回 `{output, details, params?}`。[完整参数与示例](docs/api.md)。CLI 输出文件以 `0600` 创建；默认不覆盖已有文件，`--force` 仅允许覆盖普通单链接文件，保护输入、符号链接与硬链接。私钥和口令放在本地受保护的请求文件 / stdin，不要放进 shell 历史或公共 issue。

## AI Skill

仓库提供 [skills/cipherdesk](skills/cipherdesk)。将该文件夹放入你的 AI 工具支持的 skills 目录。Codex 可安装到 `~/.codex/skills/cipherdesk`。

示例：“用 $cipherdesk 在本地为这段消息生成 SHA-256 / HMAC，输出校验结果。”Skill 使用同一套 CLI / API，提示明确算法与编码；不会声称能解密摘要。

## 验证与贡献

`npm test` 覆盖摘要标准向量、RFC 4231 HMAC、SM4 标准块向量、AES / RSA 与 Node crypto 的互操作、GCM 篡改拒绝、PBKDF2、JWT、字节格式和 CLI 文件保护。浏览器验证记录见 [docs/validation.md](docs/validation.md)。

欢迎通过 issue 描述算法、模式、编码、复现步骤和**合成示例**。不要上传实际私钥、口令或生产 token。UI 位于 `dist/`，核心位于 `src/core.mjs`；修改核心后需重新 `npm run build`。

MIT © 2026 batype。运行时依赖许可证见 [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt)。
