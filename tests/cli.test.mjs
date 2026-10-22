import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,readFile,stat,symlink,link,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
const cli=new URL('../bin/cipherdesk.mjs',import.meta.url);
const run=(args=[],input='')=>spawnSync(process.execPath,[cli.pathname,...args],{input,encoding:'utf8'});
test('CLI accepts stdin JSON, rejects bad requests without echoing sensitive input',()=>{
 const r=run([],JSON.stringify({tool:'hash',input:'abc'}));assert.equal(r.status,0);assert.match(JSON.parse(r.stdout).output,/^ba7816bf/);
 const bad=run([],'SECRET_INVALID_JSON');assert.equal(bad.status,1);assert.equal(bad.stderr.includes('SECRET'),false);assert.equal(run(['--key','a']).status,1);
});
test('CLI output is private and does not overwrite input, symlinks, hardlinks or existing files accidentally',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'cipherdesk-test-'));
 try{const input=path.join(dir,'in.json'),output=path.join(dir,'out.json'),symbolic=path.join(dir,'symbolic'),hard=path.join(dir,'hard');const original=JSON.stringify({tool:'hash',input:'abc'});await writeFile(input,original);
 assert.equal(run(['--in',input,'--out',output]).status,0);assert.equal((await stat(output)).mode&0o777,0o600);
 assert.equal(run(['--in',input,'--out',output]).status,1);assert.equal(run(['--in',input,'--out',output,'--force']).status,0);
 assert.equal(run(['--in',input,'--out',input,'--force']).status,1);assert.equal(await readFile(input,'utf8'),original);
 await symlink(input,symbolic);await link(input,hard);assert.equal(run(['--in',input,'--out',symbolic,'--force']).status,1);assert.equal(run(['--in',input,'--out',hard,'--force']).status,1);assert.equal(await readFile(input,'utf8'),original);
 }finally{await rm(dir,{recursive:true});}
});
