# 验证记录 · 2026-10-22

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
