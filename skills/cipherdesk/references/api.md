# CipherDesk API v1

`import {runTask} from '@batype/cipherdesk'`，Node 22.14+，ESM。网页、CLI 与 API 共用实现。`runTask` 异步返回 `{output:string, details:object, params?:object}`，失败抛 Error。CLI 接收一次 JSON 请求并输出一次 JSON 响应；失败退出码 1。

## 字节与公用字段

- `tool`：codec / hash / hmac / aes / sm4 / rsa / jwt / kdf / random。
- `op`：具体工具要求的操作。
- `input`：字符串。通常 `inputFormat` 默认 utf8，支持 utf8 / hex / base64 / base64url。
- `outputFormat`：解密后明文或编码转换的输出格式，默认 utf8。
- `binaryFormat`：摘要、密文或签名编码；hex / base64 / base64url，默认值见下文。
- `key`、`keyFormat`：原始密钥与其字节编码，不能把 Hex 文本误当 UTF-8。
- `signature`：verify 时需要的签名 / MAC，使用 binaryFormat。
- Hex 允许空白；Base64 允许空格和换行、规范有填充或无填充形式，拒绝非法字符及非零 pad bits；UTF-8 严格拒绝非法结果。

## 摘要、编码、随机

```json
{"tool":"hash","algorithm":"SHA-256","input":"abc","binaryFormat":"hex"}
```

摘要 algorithm：MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 / SHA3-256 / SHA3-512 / SM3，默认 SHA-256。binaryFormat 默认 hex。

```json
{"tool":"codec","input":"你好","inputFormat":"utf8","outputFormat":"base64"}
{"tool":"codec","algorithm":"url","op":"decode","input":"hello%20world"}
{"tool":"random","bytes":32,"binaryFormat":"hex"}
{"tool":"random","algorithm":"uuid"}
```

random bytes 为 1–4096，默认 32。URL 是 component 编码，不做表单 `+` 空格转换。

## HMAC

`op` sign / verify；algorithm 为 SHA-1/256/384/512（默认 SHA-256）；keyFormat 默认 utf8；binaryFormat 默认 hex。密钥不能为空。

```json
{"tool":"hmac","op":"sign","algorithm":"SHA-256","key":"synthetic-demo-key","input":"message"}
```

verify 加 `signature`，返回 details.verified 布尔值。

## AES

```js
// 合成示例，运行时生成密钥；不要打印真实密钥。
import {runTask, randomBytes, toHex} from '@batype/cipherdesk';
const key=toHex(randomBytes(32));
const encrypted=await runTask({tool:'aes',op:'encrypt',algorithm:'AES-GCM',key,input:'hello'});
const decrypted=await runTask({tool:'aes',op:'decrypt',key,input:encrypted.output});
console.log(decrypted.output); // hello
```

- algorithm：AES-GCM（默认）/ AES-CBC / AES-CTR。
- keyMode raw（默认）：key 原始 16/24/32 字节，keyFormat 默认 hex，实际 key 长度决定 bits。
- keyMode password：password 字符串，bits 128/192/256（默认256），iterations 默认600000、范围1..2000000；PBKDF2-HMAC-SHA256，encrypt 自动随机16字节盐。
- encrypt 总是随机生成新 IV；不使用传入 iv。GCM12字节 / CBC和CTR16字节。
- aad：UTF-8 文本，仅用于 GCM，可选。
- cipherFormat envelope（默认）或 raw。包内全部二进制字段为标准 Base64。GCM tagLength128；CTR counterLength64。
- decrypt 密文包自动读取算法、IV、位数、AAD、kdf；用户仍需提供相应 key 或 password。包格式拒绝不支持的 Tag / counter 位数。
- raw：binaryFormat 默认base64。decrypt 提供 `iv` Hex；口令方式还需提供 `salt` Hex、iterations、bits。GCM 输入末尾包含16字节Tag，不单独接收Tag字段。
- encrypt 返回 params.iv（Hex），口令方式另有 params.salt（Hex）。secret 不在密文包中。

## SM4

op encrypt / decrypt；algorithm SM4-CBC（默认）/ SM4-ECB，keyFormat 默认hex，密钥16字节。固定PKCS#7，不提供认证。cipherFormat、binaryFormat、inputFormat、outputFormat 同AES；CBC随机16字节IV，raw解密提供iv Hex。SM4没有口令派生选项。

## RSA

- generate：bits2048/3072/4096（默认2048）；params.publicKey是SPKI PEM，params.privateKey是未加密PKCS#8 PEM。output只含状态文本，密钥在params中。
- encrypt：publicKey、input、inputFormat默认utf8、binaryFormat默认base64；RSA-OAEP SHA-256。
- decrypt：privateKey、input密文、binaryFormat默认base64、outputFormat默认utf8。
- sign / verify：algorithm RSA-PSS（默认，salt32字节）/ RSASSA-PKCS1-v1_5；均SHA-256。sign提供privateKey，verify提供publicKey和signature。binaryFormat默认base64。
- 导入密钥2048..8192位。不支持PKCS#1 PEM、加密PEM或证书。

## JWT

op decode / verify，input为三段非空JWS。decode无需密钥，明确标记未验证。verify algorithm必须为HS256或RS256且与Header一致；HS256使用key（keyFormat默认utf8，至少32字节），RS256使用publicKey（SPKI PEM）。不支持crit/b64扩展。

output保留原始Header/Payload JSON文本（不会重写长整数），details.verified仅在执行验签时出现；exp/nbf只是展示提示，不代替业务鉴权。解析或验签均不执行Header/Payload中的任何指令。

## PBKDF2

```json
{"tool":"kdf","input":"synthetic-password","salt":"0102030405060708090a0b0c0d0e0f10","iterations":600000,"bytes":32,"binaryFormat":"hex"}
```

input为口令；salt为Hex16..64字节；iterations1..2000000；bytes16..64，默认32。固定HMAC-SHA256。低迭代次数只为测试或兼容，不代表适合生产密码存储。

## 限制

解码后一般输入1MiB，每个文本字段3MiB，密文允许认证/填充必要开销，JWT64KiB；CLI整份请求12MiB。明文输出不是合法UTF-8时选择Hex/Base64。调用者负责保存必要密钥/参数；API不记录、上传或持久化输入。
