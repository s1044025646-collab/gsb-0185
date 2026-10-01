/**
 * 有长度边界的规范编码（TLV：Tag-Length-Value）。
 *
 * 所有哈希输入都通过 encodeFields 序列化为无歧义字节串，
 * 杜绝字符串拼接造成的上下文混淆（例如 ["ab","c"] 与 ["a","bc"]）。
 *
 * 字段类型标签：
 *   0x01 字节序列（length 为大端 uint32）
 *   0x02 非负整数（定长最小大端表示，带长度前缀）
 *   0x03 UTF-8 文本
 */

import { createHash } from "node:crypto";

export type CanonicalField =
  | { type: "bytes"; value: Buffer }
  | { type: "int"; value: bigint }
  | { type: "text"; value: string };

const TAG_BYTES = 0x01;
const TAG_INT = 0x02;
const TAG_TEXT = 0x03;

export function bytes(value: Buffer): CanonicalField {
  return { type: "bytes", value };
}

export function int(value: bigint): CanonicalField {
  if (value < 0n) throw new Error("canonical encoding 仅支持非负整数");
  return { type: "int", value };
}

export function text(value: string): CanonicalField {
  return { type: "text", value };
}

function writeLength(length: number): Buffer {
  if (length > 0xffffffff) throw new Error("字段长度超过 uint32 上限");
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(length, 0);
  return buf;
}

function encodeField(field: CanonicalField): Buffer {
  if (field.type === "bytes") {
    return Buffer.concat([Buffer.from([TAG_BYTES]), writeLength(field.value.length), field.value]);
  }
  if (field.type === "int") {
    let hex = field.value.toString(16);
    if (hex.length % 2 === 1) hex = "0" + hex;
    const body = field.value === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
    return Buffer.concat([Buffer.from([TAG_INT]), writeLength(body.length), body]);
  }
  const body = Buffer.from(field.value, "utf8");
  return Buffer.concat([Buffer.from([TAG_TEXT]), writeLength(body.length), body]);
}

/**
 * 将字段列表编码为一个带总长度边界的 TLV 帧：
 *   MAGIC(4) | FIELD_COUNT(uint32) | FIELD...
 */
export function encodeFields(domain: string, fields: CanonicalField[]): Buffer {
  const domainBytes = Buffer.from(domain, "utf8");
  const header = Buffer.alloc(8);
  header.write("SCP1", 0, 4, "ascii"); // Schnorr Canonical Proof v1
  header.writeUInt32BE(fields.length, 4);
  return Buffer.concat([
    Buffer.from([TAG_TEXT]),
    writeLength(domainBytes.length),
    domainBytes,
    header,
    ...fields.map(encodeField),
  ]);
}

export function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

/**
 * 域分离哈希：对 (domain, fields) 做 SHA-256，返回 BigInt。
 * domain 用于绑定用途（如 "FS_CHALLENGE_V1"）。
 */
export function hashFieldsToBigInt(domain: string, fields: CanonicalField[]): bigint {
  return BigInt("0x" + sha256(encodeFields(domain, fields)).toString("hex"));
}
