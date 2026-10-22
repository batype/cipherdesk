# Changelog

## 1.0.1 · 2026-10-22

- 修复Chromium浏览器无法使用AES-192的问题；GCM、CBC和CTR均支持原始密钥及PBKDF2口令派生。
- AES-192使用noble-ciphers兼容实现，AES-128/256继续使用Web Crypto。保留既有密文包、认证Tag、填充与CTR低64位计数格式。
- 扩展128/192/256互操作和浏览器兼容回归；覆盖篡改拒绝、计数器回绕及1MiB输入边界。

## 1.0.0 · 2026-10-22

- 首次发布本地密码工具箱、Node API/CLI及AI skill。
