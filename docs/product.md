# 需求分析 · 2026-10-22

定位：给前后端开发者一个打开即用的本地密码工作台，集中解决接口联调时的编码、签名、密文参数与 JWT 检查问题。

## 场景与取舍

| 场景 | 需要完成的任务 | 首版实现 |
|---|---|---|
| 接口请求签名不一致 | 明确字节编码、密钥与摘要，再验签 | HMAC生成/验证、RSA签名/验签 |
| 对接第三方加密接口 | 选择模式，明确IV、密钥编码、Tag和填充 | AES原始密文、参数提示、SM4兼容 |
| 本地保护一小段内容 | 加密后能可靠还原 | 默认AES-GCM与带参数密文包 |
| 登录token排错 | 解析内容、检查签名是否匹配 | JWT解码与HS256/RS256验签 |
| 日常数据转换 | 少开几个网页 | 编码、摘要、随机值、PBKDF2 |

这些场景具有重复出现的可能，但目前没有本项目的真实留存数据。需验证的核心假设是：清楚展示参数、少做错误默认值，比单纯增加算法数更有复用价值。

同类已有 [CyberChef](https://github.com/gchq/CyberChef)，提供广泛的数据操作与组合配方，也支持本地处理。本项目不宣称独创“本地密码工具”；差异在中文聚焦界面、默认GCM、可还原的参数包、直接的编码约定，以及相同核心的CLI/API/skill。市场上已有成熟项目并不能证明本工具会获得关注或留存。

## 传播与首屏

用“明文 → 密文包 → 一键转输入 → 解密还原”的15秒演示表现价值；加上明暗模式与国密入口。避免以“MD5解密”“无所不能”吸引点击。初期观察首次处理是否完成、参数错误集中在哪里，以及是否主动再次使用；不偷偷加入追踪脚本。

## 首版边界

9个工具分组。范围固定为README矩阵；不含后端、账户、云端历史、大文件流式加密、密码破解、证书管理、SM2或所有OpenSSL参数的兼容。保留用户主动导出与复制；仅主题持久化。算法能力与兼容限制在UI与文档中同时说明。

## 实现依据

- [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)：AES、RSA、HMAC、PBKDF2交给平台实现，不自行写密码算法。
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)：优先带认证模式；旧模式清晰提示限制。
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)：PBKDF2-HMAC-SHA256默认600000；快速摘要与密码存储区分。
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)：OAEP消息长度k−2hLen−2，2048位与SHA256组合最多190字节。
- [noble-hashes](https://github.com/paulmillr/noble-hashes)：MD5与SHA3实现。
- [sm-crypto](https://github.com/JuneAndGreen/sm-crypto)：SM3/SM4，包装层严格检查字节长度与PKCS#7。

这些选择是开发调试工具的工程取舍，不构成独立安全审计或生产密钥管理方案。
