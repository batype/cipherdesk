# 验证记录 · 2026-10-22

## v1.0.1 · AES-192 兼容修复

- 根因已在线复现：Chromium Web Crypto对24字节密钥返回`192-bit AES keys are not supported`；Node原生实现同样输入可以运行。参见[Chromium AES实现](https://raw.githubusercontent.com/chromium/chromium/main/components/webcrypto/algorithms/aes.cc)。
- 修复范围：仅AES-192通过noble-ciphers实现GCM/CBC/CTR；AES-128/256仍走Web Crypto。保留v1密文包、GCM末尾16字节Tag、CBC的PKCS#7及CTR低64位计数约定。原始密钥和PBKDF2派生均覆盖。没有迁移前端框架或处理其他审查项。
- `npm test`：22组通过。原AES互操作测试扩展为128/192/256 × GCM/CBC/CTR；新增模拟浏览器拒绝192位原生密钥、外部密文解密、口令派生、CTR跨32/64位边界、认证/填充错误和空/整块/最大1MiB输入测试。
- 浏览器真实操作：三种模式 × 三种位数共9种原始密钥组合均加密后解密还原；AES-192三种模式的口令派生也通过，使用默认600000次迭代。控制台无error/warn。
- Node发布包重新在工程外安装，验证AES-192与CLI。上线后的复测结果见本次GitHub Release说明。

下面保留v1.0.0初版验证记录。

## 自动化

Node.js24.13.0，`npm test`：16组通过。

- 严格字节转换、中文与emoji、非法Hex/Base64 pad bits、非法UTF-8、输入上限。
- MD5/SHA1/SHA2/SHA3与Node crypto比较，SM3标准abc向量，RFC4231 HMAC标准向量与错消息验签。
- AES GCM/CBC/CTR由Node crypto独立解密；新IV、GCM篡改拒绝、错误口令拒绝、PBKDF2原始/密文包还原、1MiB边界、AAD包内优先。
- SM4标准块向量、空文本/整块填充往返，CBC/ECB均由OpenSSL独立解密。
- RSA-OAEP两向互操作、最大长度拒绝，PSS/PKCS1 SHA256签名验证。
- JWT HS256/RS256、显式算法匹配、弱HS256密钥拒绝、原始长整数保留、签名正确但已过期的区分。
- PBKDF2与Node比较、非法参数、随机值长度/UUID格式。
- CLI stdin请求、错误不回显输入、0600文件、覆盖保护、输入/符号链接/硬链接保护。

## 浏览器

Codex内置Chromium，真实UI操作验证：

- 九类工具各自的示例均得到结果，控制台无error/warn。
- AES加密→结果转输入→解密还原；RSA生成密钥→加密→解密还原。
- 处理后参数自动折叠，生成RSA密钥时保持展开，可下载公/私钥PEM。
- 1280×960桌面、390×844手机无页面横向溢出；手机工具导航自身允许横向滚动。
- 亮/暗切换；刷新后主题选择保留；“清空全部”移除输入、密钥与结果并禁用结果按钮。

截图：[亮色](preview-light.png)、[暗色](preview-dark.png)、[手机](preview-mobile.png)。截图只使用合成输入和临时随机密钥，不含生产数据。

## 包与skill

已打包并在项目以外的目录安装tarball，验证API和CLI。Skill通过quick_validate校验，参考中的AES示例用实际API执行字节往返。正式npm公开安装状态以README或最终交付记录为准。

## 未覆盖

未进行独立密码学审计；未在Safari/Firefox、真实iOS/Android设备、所有RSA位数和每个格式组合上穷举。单元测试与内置浏览器验证不能等价于所有浏览器兼容性保证。
