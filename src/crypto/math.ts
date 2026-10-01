/**
 * 大整数模运算工具。全部使用原生 BigInt 实现，不依赖外部密码库。
 * 仅用于教学演示，不应用于生产环境。
 */

import { randomBytes, randomInt } from "node:crypto";

export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod <= 0n) throw new Error("modPow: 模数必须为正整数");
  let result = 1n % mod;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/** 扩展欧几里得算法，返回 [gcd, x, y] 使 a*x + b*y = gcd。 */
export function extendedGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  let [oldR, r] = [a, b];
  let [oldS, s] = [1n, 0n];
  let [oldT, t] = [0n, 1n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return [oldR, oldS, oldT];
}

/** 模逆；当逆元不存在时抛出异常。 */
export function modInverse(value: bigint, mod: bigint): bigint {
  const [gcd, x] = extendedGcd(((value % mod) + mod) % mod, mod);
  if (gcd !== 1n) throw new Error("modInverse: 逆元不存在");
  return ((x % mod) + mod) % mod;
}

/**
 * Miller-Rabin 概率素性测试。
 * @param rounds  witness 轮数（默认 24）
 */
export function isProbablePrime(n: bigint, rounds = 24): boolean {
  if (n < 2n) return false;
  const smallPrimes = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  for (const sp of smallPrimes) {
    if (n === sp) return true;
    if (n % sp === 0n) return false;
  }
  let d = n - 1n;
  let s = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1n;
  }
  witness: for (let i = 0; i < rounds; i++) {
    const a = randomWitness(n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let r = 1n; r < s; r++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) continue witness;
      if (x === 1n) return false;
    }
    return false;
  }
  return true;
}

function randomWitness(n: bigint): bigint {
  const span = n - 3n;
  const byteLen = Math.ceil(span.toString(16).length / 2);
  for (;;) {
    const raw = BigInt("0x" + randomBytes(byteLen).toString("hex")) % span;
    const a = raw + 2n;
    if (a >= 2n && a <= n - 2n) return a;
  }
}

export interface RandomSource {
  /** 返回 [0, bound) 内的随机 BigInt；bound 必须为正。 */
  randomBigInt(bound: bigint): bigint;
  /** 返回 [min, max] 内的随机安全整数。 */
  randomInt(maxExclusive: number): number;
}

/** 默认随机源：基于系统密码学随机字节（crypto.randomBytes）。 */
export const systemRandomSource: RandomSource = {
  randomBigInt(bound: bigint): bigint {
    if (bound <= 0n) throw new Error("randomBigInt: 上界必须为正");
    const byteLen = Math.max(1, Math.ceil(bound.toString(16).length / 2));
    const limit = (1n << BigInt(byteLen * 8)) - (1n << BigInt(byteLen * 8)) % bound;
    for (;;) {
      const candidate = BigInt("0x" + randomBytes(byteLen).toString("hex"));
      // 拒绝采样，消除模偏差
      if (candidate < limit) return candidate % bound;
    }
  },
  randomInt(maxExclusive: number): number {
    return randomInt(maxExclusive);
  },
};

/**
 * 在 [1, upperBound - 1] 中均匀抽取标量。
 * upperBound 一般为子群阶 q。
 */
export function randomScalarInField(upperBound: bigint, rng: RandomSource = systemRandomSource): bigint {
  if (upperBound <= 2n) throw new Error("randomScalarInField: 阶过小");
  return rng.randomBigInt(upperBound - 1n) + 1n;
}

/** 构造确定性随机源（仅供测试），由字节序列循环驱动拒绝采样。 */
export function deterministicRandomSource(seedBytes: Buffer): RandomSource {
  let counter = 0;
  const nextByte = (): number => {
    const v = seedBytes[counter % seedBytes.length] ?? 1;
    counter++;
    return v;
  };
  return {
    randomBigInt(bound: bigint): bigint {
      const byteLen = Math.max(1, Math.ceil(bound.toString(16).length / 2));
      const buf = Buffer.alloc(byteLen);
      for (let i = 0; i < byteLen; i++) buf[i] = nextByte();
      return BigInt("0x" + buf.toString("hex")) % bound;
    },
    randomInt(maxExclusive: number): number {
      return nextByte() % maxExclusive;
    },
  };
}
