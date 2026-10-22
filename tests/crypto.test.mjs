import test from 'node:test';
import assert from 'node:assert/strict';
import {createDecipheriv,createHash,createHmac,publicEncrypt,privateDecrypt,sign,verify,pbkdf2Sync,constants} from 'node:crypto';
import {runTask,decodeBytes,encodeBytes,MAX_BYTES} from '../src/core.mjs';

test('strict byte codecs preserve Unicode / binary and reject malformed data',async()=>{
 for(const f of ['utf8','hex','base64','base64url'])assert.equal(encodeBytes(decodeBytes(encodeBytes(new TextEncoder().encode('你好 🔐'),f),f),'utf8'),'你好 🔐');
 for(const [s,f] of [['a','hex'],['gg','hex'],['Zh==','base64'],['Zg=','base64'],['Zg$','base64'],['+/==','base64url']])assert.throws(()=>decodeBytes(s,f));
 assert.throws(()=>encodeBytes(new Uint8Array([255]),'utf8'),/UTF-8/);
 assert.throws(()=>decodeBytes('a'.repeat(MAX_BYTES+1)),/1 MiB/);
 assert.equal((await runTask({tool:'codec',algorithm:'url',op:'decode',input:'a%2Bb%20c'})).output,'a+b c');
 await assert.rejects(runTask({tool:'codec',algorithm:'url',op:'decode',input:'%ff'}));
});
test('hash known answers and OpenSSL SHA3 interoperability',async()=>{
 for(const [algorithm,node] of [['MD5','md5'],['SHA-1','sha1'],['SHA-256','sha256'],['SHA-384','sha384'],['SHA-512','sha512'],['SHA3-256','sha3-256'],['SHA3-512','sha3-512']])assert.equal((await runTask({tool:'hash',algorithm,input:'abc'})).output,createHash(node).update('abc').digest('hex'));
 assert.equal((await runTask({tool:'hash',algorithm:'SM3',input:'abc'})).output,'66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
});
test('HMAC RFC4231 and verification rejects changed content',async()=>{
 const job={tool:'hmac',op:'sign',algorithm:'SHA-256',key:'0b'.repeat(20),keyFormat:'hex',input:'Hi There'};
 const {output}=await runTask(job);assert.equal(output,'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
 assert.equal((await runTask({...job,op:'verify',signature:output})).details.verified,true);
 assert.equal((await runTask({...job,op:'verify',signature:output,input:'changed'})).details.verified,false);
});
test('AES modes interoperate with node crypto; fresh IV and authenticated tamper rejection',async()=>{
 for(const algorithm of ['AES-GCM','AES-CBC','AES-CTR']){
  const job={tool:'aes',op:'encrypt',algorithm,key:'21'.repeat(32),input:'中文 message 🔐',aad:algorithm==='AES-GCM'?'context':''};
  const encrypted=await runTask(job),bundle=JSON.parse(encrypted.output),again=JSON.parse((await runTask(job)).output);assert.notEqual(bundle.iv,again.iv);assert.equal(bundle.key,undefined);
  const cipher=Buffer.from(bundle.ciphertext,'base64'),dec=createDecipheriv(algorithm.toLowerCase().replace('aes-','aes-256-'),Buffer.from(job.key,'hex'),Buffer.from(bundle.iv,'base64'));
  let data=cipher;if(algorithm==='AES-GCM'){dec.setAuthTag(cipher.subarray(-16));dec.setAAD(Buffer.from(job.aad));data=cipher.subarray(0,-16);}
  assert.equal(Buffer.concat([dec.update(data),dec.final()]).toString(),job.input);
  assert.equal((await runTask({...job,op:'decrypt',input:encrypted.output})).output,job.input);
  if(algorithm==='AES-GCM'){cipher[0]^=1;await assert.rejects(runTask({...job,op:'decrypt',input:JSON.stringify({...bundle,ciphertext:cipher.toString('base64')})}),/解密失败/);await assert.rejects(runTask({...job,op:'decrypt',input:JSON.stringify({...bundle,tagLength:96})}),/Tag/);}
 }
});
test('AES password envelope and raw ciphertext are reusable',async()=>{
 const job={tool:'aes',op:'encrypt',algorithm:'AES-GCM',keyMode:'password',password:'testing-only',iterations:1000,bits:128,input:'derived message'};
 const enc=await runTask(job);assert.equal((await runTask({tool:'aes',op:'decrypt',password:job.password,input:enc.output})).output,job.input);
 await assert.rejects(runTask({tool:'aes',op:'decrypt',password:'wrong',input:enc.output}));
 const raw=await runTask({...job,cipherFormat:'raw',binaryFormat:'hex'});
 assert.equal((await runTask({...job,op:'decrypt',cipherFormat:'raw',binaryFormat:'hex',input:raw.output,iv:raw.params.iv,salt:raw.params.salt})).output,job.input);
});
test('AES maximum input survives envelope overhead',async()=>{
 const job={tool:'aes',op:'encrypt',key:'01'.repeat(16),input:'x'.repeat(MAX_BYTES)};const enc=await runTask(job);assert.equal((await runTask({...job,op:'decrypt',input:enc.output})).output.length,MAX_BYTES);
});
test('SM4 standard block vector, PKCS7 roundtrip and invalid padding rejection',async()=>{
 const key='0123456789abcdeffedcba9876543210';const vector=await runTask({tool:'sm4',op:'encrypt',algorithm:'SM4-ECB',key,input:key,inputFormat:'hex',cipherFormat:'raw',binaryFormat:'hex'});assert.equal(vector.output.slice(0,32),'681edf34d206965e86b3e94f536e4246');
 for(const algorithm of ['SM4-CBC','SM4-ECB'])for(const input of ['','你好 SM4','a'.repeat(16)]){const job={tool:'sm4',op:'encrypt',algorithm,key,input};const enc=await runTask(job);assert.equal((await runTask({...job,op:'decrypt',input:enc.output})).output,input);}
 await assert.rejects(runTask({tool:'sm4',op:'decrypt',key,cipherFormat:'raw',iv:'00'.repeat(16),input:'00',binaryFormat:'hex'}),/16 字节倍数/);
});
test('SM4 CBC and ECB decrypt with Node/OpenSSL independently',async()=>{
 for(const algorithm of ['SM4-CBC','SM4-ECB']){
  const key='42'.repeat(16),input='国密 OpenSSL compatibility';
  const bundle=JSON.parse((await runTask({tool:'sm4',op:'encrypt',algorithm,key,input})).output);
  const native=createDecipheriv(algorithm.toLowerCase(),Buffer.from(key,'hex'),bundle.iv?Buffer.from(bundle.iv,'base64'):null);
  assert.equal(Buffer.concat([native.update(Buffer.from(bundle.ciphertext,'base64')),native.final()]).toString(),input);
 }
});
test('envelope AAD takes precedence over stale job parameters',async()=>{
 const key='02'.repeat(16),cipher=(await runTask({tool:'aes',op:'encrypt',key,input:'hello'})).output;
 assert.equal((await runTask({tool:'aes',op:'decrypt',key,input:cipher,aad:'stale'})).output,'hello');
});
let pem;
test('RSA OAEP interoperates with OpenSSL and enforces maximum message size',async()=>{
 pem=(await runTask({tool:'rsa',op:'generate',bits:2048})).params;
 const ciphertext=await runTask({tool:'rsa',op:'encrypt',...pem,input:'private message'});
 assert.equal(privateDecrypt({key:pem.privateKey,oaepHash:'sha256'},Buffer.from(ciphertext.output,'base64')).toString(),'private message');
 const external=publicEncrypt({key:pem.publicKey,oaepHash:'sha256'},Buffer.from('from node')).toString('base64');assert.equal((await runTask({tool:'rsa',op:'decrypt',...pem,input:external})).output,'from node');
 await assert.rejects(runTask({tool:'rsa',op:'encrypt',...pem,input:'a'.repeat(191)}),/190/);
});
test('RSA PSS and PKCS1 SHA256 signature interoperability',async()=>{
 if(!pem)pem=(await runTask({tool:'rsa',op:'generate'})).params;
 for(const algorithm of ['RSA-PSS','RSASSA-PKCS1-v1_5']){const job={tool:'rsa',op:'sign',algorithm,...pem,input:'signature content'};const {output}=await runTask(job);const options={key:pem.publicKey,...(algorithm==='RSA-PSS'?{padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}:{})};assert.equal(verify('sha256',Buffer.from(job.input),options,Buffer.from(output,'base64')),true);assert.equal((await runTask({...job,op:'verify',signature:output})).details.verified,true);assert.equal((await runTask({...job,op:'verify',signature:output,input:'wrong'})).details.verified,false);}
});
test('JWT preserves raw long numbers, explicitly verifies signature and rejects alg confusion',async()=>{
 const key='demo-secret-longer-than-32-bytes-only',header=Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),payload=Buffer.from('{"id":1234567890123456789,"exp":1}').toString('base64url'),data=header+'.'+payload,token=data+'.'+createHmac('sha256',key).update(data).digest('base64url');
 assert.match((await runTask({tool:'jwt',op:'decode',input:token})).output,/1234567890123456789/);
 const job={tool:'jwt',op:'verify',algorithm:'HS256',key,input:token};const result=await runTask(job);assert.equal(result.details.verified,true);assert.equal(result.details.exp,'已过期');
 await assert.rejects(runTask({...job,algorithm:'RS256'}),/alg/);await assert.rejects(runTask({...job,key:'short'}),/32 字节/);
 const rsData=Buffer.from('{"alg":"RS256"}').toString('base64url')+'.'+payload;const rsToken=rsData+'.'+sign('sha256',Buffer.from(rsData),pem.privateKey).toString('base64url');assert.equal((await runTask({tool:'jwt',op:'verify',algorithm:'RS256',publicKey:pem.publicKey,input:rsToken})).details.verified,true);
});
test('PBKDF2 matches node and rejects out of bounds parameters',async()=>{
 const job={tool:'kdf',input:'口令',salt:'ab'.repeat(16),iterations:1000,bytes:32};assert.equal((await runTask(job)).output,pbkdf2Sync(job.input,Buffer.from(job.salt,'hex'),1000,32,'sha256').toString('hex'));
 await assert.rejects(runTask({...job,iterations:2000001}));await assert.rejects(runTask({...job,salt:'aa'}));
});
test('random generation provides requested size and UUID v4',async()=>{
 const a=await runTask({tool:'random',bytes:32}),b=await runTask({tool:'random',bytes:32});assert.equal(a.output.length,64);assert.notEqual(a.output,b.output);assert.match((await runTask({tool:'random',algorithm:'uuid'})).output,/^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/);await assert.rejects(runTask({tool:'random',bytes:4097}));
});
