export const VERSION: string;
export const MAX_BYTES: number;
export type ByteFormat='utf8'|'hex'|'base64'|'base64url';
export interface Task {
 tool:'codec'|'hash'|'hmac'|'aes'|'sm4'|'rsa'|'jwt'|'kdf'|'random';
 op?:'encrypt'|'decrypt'|'sign'|'verify'|'generate'|'decode'|'encode'|'convert'|'digest'|'derive';
 input?:string; algorithm?:string;
 inputFormat?:ByteFormat; outputFormat?:ByteFormat; binaryFormat?:Exclude<ByteFormat,'utf8'>;
 key?:string; keyFormat?:ByteFormat; keyMode?:'raw'|'password'; password?:string;
 bits?:128|192|256|2048|3072|4096; iterations?:number; salt?:string; iv?:string; aad?:string;
 cipherFormat?:'envelope'|'raw'; signature?:string; publicKey?:string; privateKey?:string; bytes?:number;
}
export interface TaskResult {output:string;details:Record<string,string|number|boolean>;params?:{iv?:string;salt?:string;publicKey?:string;privateKey?:string};}
export function runTask(job:Task):Promise<TaskResult>;
export function decodeBytes(input:string,format?:ByteFormat,max?:number):Uint8Array;
export function encodeBytes(bytes:Uint8Array,format?:ByteFormat):string;
export function toHex(bytes:Uint8Array):string;
export function randomBytes(size:number):Uint8Array;
