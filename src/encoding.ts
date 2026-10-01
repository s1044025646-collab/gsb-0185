// 规范编码：带长度边界的 TLV（Type-Length-Value）编码，避免字符串拼接歧义。
// 所有参与哈希的字段均以 (tag, bytes) 形式编码，并显式写入 8 字节大端长度。
import { createHash } from "node:crypto";

export type TlvValue = string | Uint8Array | bigint;

const enc = new TextEncoder();

export function u64Length(n: number): Buffer {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error(`非法长度: ${n}`);
  }
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(n));
  return buf;
}

function asBytes(v: TlvValue): Buffer {
  if (typeof v === "string") return Buffer.from(enc.encode(v));
  if (typeof v === "bigint") {
    if (v < 0n) throw new Error("不允许负整数进入 TLV 编码");
    let hex = v.toString(16);
    if (hex.length % 2 === 1) hex = "0" + hex;
    return hex === "0" ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  }
  return Buffer.from(v);
}

/** 编码单个 TLV 项。tag 必须为单字节非负数（0..255）。 */
export function tlv(tag: number, value: TlvValue): Buffer {
  if (!Number.isInteger(tag) || tag < 0 || tag > 255) {
    throw new Error(`非法 TLV tag: ${tag}`);
  }
  const body = asBytes(value);
  return Buffer.concat([Buffer.from([tag]), u64Length(body.length), body]);
}

/** 规范字节序列：逐项 TLV 后整体再加一层长度边界，保证无歧义、可流式校验。 */
export function canonical(...items: Array<[number, TlvValue]>): Buffer {
  const parts = items.map(([tag, value]) => tlv(tag, value));
  const inner = Buffer.concat(parts);
  return Buffer.concat([u64Length(inner.length), inner]);
}

/** 对规范字节序列计算 SHA-256，返回 bigint（尚未对阶取模）。 */
export function sha256Bigint(data: Buffer): bigint {
  return BigInt("0x" + createHash("sha256").update(data).digest("hex"));
}

export function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}
