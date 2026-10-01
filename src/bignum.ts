// BigInt 模运算与系统密码学安全随机数。
import { randomBytes, randomUUID } from "node:crypto";

/** 模幂 a^e mod m（平方-乘法）。 */
export function modPow(a: bigint, e: bigint, m: bigint): bigint {
  if (m <= 0n) throw new Error("模数必须为正");
  let result = 1n;
  let base = ((a % m) + m) % m;
  let exp = e;
  if (exp < 0n) throw new Error("本实验不支持负指数");
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

/** 模逆（扩展欧几里得），要求 n 与 m 互素。 */
export function modInverse(n: bigint, m: bigint): bigint {
  let [oldR, r] = [((n % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error("模逆不存在");
  return ((oldS % m) + m) % m;
}

export type RandomSource = (bytes: number) => Buffer;

/** 默认随机源：系统 CSPRNG（/dev/urandom / CryptGenRandom），无固定种子。 */
export const systemRandom: RandomSource = (bytes) => randomBytes(bytes);

// 供测试注入的确定性随机源工具：由字节序列循环提供
export function deterministicRandom(seedBytes: Buffer): RandomSource {
  if (seedBytes.length === 0) throw new Error("确定性随机源至少需要 1 字节种子");
  let pos = 0;
  return (bytes: number) => {
    const out = Buffer.alloc(bytes);
    for (let i = 0; i < bytes; i++) {
      out[i] = seedBytes[pos % seedBytes.length] ?? 0;
      pos++;
    }
    return out;
  };
}

/** 在 [min, max] 内均匀采样（拒绝采样，消除模偏差）。 */
export function randomBigIntBetween(min: bigint, max: bigint, rand: RandomSource = systemRandom): bigint {
  if (max < min) throw new Error("随机区间非法：max < min");
  const span = max - min + 1n;
  const bitLen = span.toString(2).length;
  const byteLen = Math.ceil(bitLen / 8);
  const mask = (1n << BigInt(bitLen)) - 1n;
  // 最多拒绝若干次，保证合法范围且无模偏差
  for (let attempt = 0; attempt < 10000; attempt++) {
    const raw = BigInt("0x" + rand(byteLen).toString("hex")) & mask;
    if (raw < span) return min + raw;
  }
  throw new Error("随机采样失败（拒绝采样未命中）");
}

/** 采样合法私有标量 x ∈ [1, q-1]。 */
export function randomScalar(q: bigint, rand: RandomSource = systemRandom): bigint {
  return randomBigIntBetween(1n, q - 1n, rand);
}

export const uuid = (): string => randomUUID();



