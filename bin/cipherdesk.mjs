#!/usr/bin/env node
import { readFile, open, lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { runTask, VERSION } from "../src/core.mjs";
const help = `CipherDesk ${VERSION} — local developer crypto tools

Usage: cipherdesk [--in request.json] [--out result.json] [--force]
       cipherdesk --help | --version

One JSON request from a UTF-8 file or stdin; one JSON result to stdout or file.
Example: {"tool":"hash","algorithm":"SHA-256","input":"abc"}
Tools: codec, hash, hmac, aes, sm4, rsa, jwt, kdf, random.
API schema and examples: https://github.com/batype/cipherdesk#node-api--cli
Put keys/passwords in the request, never in command-line arguments.
--out creates a 0600 file; --force permits replacing an existing regular file.
Existing symlinks, hardlinks and the input file are protected.
`;
try {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log(help);
    process.exit(0);
  }
  if (args.length === 1 && args[0] === "--version") {
    console.log(VERSION);
    process.exit(0);
  }
  let inputFile, outputFile, force = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--force") {
      force = true;
      continue;
    }
    if (!["--in", "--out"].includes(args[i]) || !args[i + 1] || args[i + 1].startsWith("--")) throw Error("未知参数或缺少值；使用 --help 查看用法");
    if (args[i] === "--in") {
      if (inputFile) throw Error("--in 重复");
      inputFile = args[++i];
    } else {
      if (outputFile) throw Error("--out 重复");
      outputFile = args[++i];
    }
  }
  const cap = 12 * 1024 * 1024;
  let bytes;
  if (inputFile) {
    const handle = await open(inputFile, "r");
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size > cap) throw Error("请求文件需为不超过 12 MiB 的普通文件");
      bytes = await handle.readFile();
    } finally {
      await handle.close();
    }
  } else {
    const chunks = [];
    let length = 0;
    for await (const chunk of process.stdin) {
      length += chunk.length;
      if (length > cap) throw Error("请求最多 12 MiB");
      chunks.push(chunk);
    }
    bytes = Buffer.concat(chunks);
  }
  if (bytes.length > cap) throw Error("请求最多 12 MiB");
  let job;
  try {
    job = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw Error("请求必须为 UTF-8 JSON 对象");
  }
  const result = JSON.stringify(await runTask(job), null, 2) + "\n";
  if (!outputFile) process.stdout.write(result);
  else {
    const target = path.resolve(outputFile);
    let info;
    try {
      info = await lstat(target);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (inputFile && target === await realpath(inputFile)) throw Error("不能覆盖输入文件");
    if (info && (!info.isFile() || info.nlink !== 1)) throw Error("不覆盖符号链接、硬链接或非普通文件");
    if (info && !force) throw Error("输出文件已存在；换一个路径或显式使用 --force");
    const { constants } = await import("node:fs");
    const handle = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | (info ? 0 : constants.O_EXCL), 384);
    try {
      const now = await handle.stat();
      if (!now.isFile() || now.nlink !== 1 || info && (now.ino !== info.ino || now.dev !== info.dev)) throw Error("输出路径已变化，停止写入");
      if (inputFile) {
        const source = await lstat(await realpath(inputFile));
        if (now.ino === source.ino && now.dev === source.dev) throw Error("不能覆盖输入文件");
      }
      await handle.chmod(384);
      await handle.truncate(0);
      await handle.writeFile(result);
    } finally {
      await handle.close();
    }
  }
} catch (error) {
  console.error("CipherDesk: " + error.message);
  process.exitCode = 1;
}
