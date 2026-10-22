import { build } from "esbuild";
await build({ entryPoints: ["src/worker.mjs"], outfile: "dist/worker.bundle.mjs", bundle: true, format: "esm", platform: "browser", target: "es2022", minify: true, legalComments: "eof" });
import { readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = fileURLToPath(new URL("../", import.meta.url));
const files = [];
async function walk(dir2) {
  for (const e of await readdir(dir2, { withFileTypes: true })) {
    if (e.name.startsWith(".") && ![".github", ".gitignore"].includes(e.name) || ["node_modules", "cipherdesk-source.zip"].includes(e.name) || e.name.endsWith(".tgz") || e.name.endsWith(".log") || e.isSymbolicLink()) continue;
    const full = path.join(dir2, e.name);
    if (e.isDirectory()) await walk(full);
    else files.push(full);
  }
}
await walk(root);
const crcTable = Array.from({ length: 256 }, (_, n) => {
  for (let k = 0; k < 8; k++) n = n & 1 ? 3988292384 ^ n >>> 1 : n >>> 1;
  return n >>> 0;
});
function crc32(b) {
  let n = 4294967295;
  for (const x of b) n = crcTable[(n ^ x) & 255] ^ n >>> 8;
  return (n ^ 4294967295) >>> 0;
}
const chunks = [], directory = [];
let offset = 0;
for (const file of files.sort()) {
  const data = await readFile(file), name = Buffer.from("cipherdesk/" + path.relative(root, file).split(path.sep).join("/")), crc = crc32(data);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(67324752);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(2048, 6);
  local.writeUInt16LE(33, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  chunks.push(local, name, data);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(33639248);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(2048, 8);
  central.writeUInt16LE(33, 14);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt32LE(offset, 42);
  directory.push(central, name);
  offset += local.length + name.length + data.length;
}
const dir = Buffer.concat(directory), end = Buffer.alloc(22);
end.writeUInt32LE(101010256);
end.writeUInt16LE(files.length, 8);
end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(dir.length, 12);
end.writeUInt32LE(offset, 16);
await writeFile(path.join(root, "dist/cipherdesk-source.zip"), Buffer.concat([...chunks, dir, end]));
console.log(`Ready: dist/ · ${files.length} source files included in the downloadable MIT source ZIP.`);
