// 群参数定义与校验。
// 群：Z_p* 中阶为素数 q 的子群，生成元 g。要求 q | (p-1)，g^q = 1，且 g != 1。
import { modPow } from "./bignum.js";

export interface GroupParams {
  /** 协议版本标签 */
  version: string;
  /** 参数集合标识 */
  label: string;
  /** 大素数模数（十六进制字符串，小参数用十进制也可，统一用十进制） */
  p: bigint;
  /** 子群阶（素数） */
  q: bigint;
  /** 生成元 */
  g: bigint;
  /** 是否为明确标注的不安全小参数 */
  unsafeSmall: boolean;
}

export interface ParamCheckResult {
  ok: boolean;
  errors: string[];
  notes: string[];
}

/** 大数素性判断：小参数走试除，大参数用 Miller-Rabin（Node 不直接暴露素性测试）。 */
export function isProbablePrime(n: bigint, rounds = 20): boolean {
  if (n < 2n) return false;
  for (const s of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === s) return true;
    if (n % s === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r++;
  }
  for (let i = 0; i < rounds; i++) {
    const a = pseudoRandomBetween(2n, n - 2n, i);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let j = 0n; j < r - 1n; j++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

// Miller-Rabin 使用确定性 PRNG 选取基（基的随机性仅影响错误概率，不影响安全性结论）
function pseudoRandomBetween(min: bigint, max: bigint, seed: number): bigint {
  let s = (BigInt(seed + 1) * 0x9e3779b97f4a7c15n + 0xdeadbeefn) & 0xffffffffffffffffn;
  const range = max - min + 1n;
  let acc = 0n;
  for (let i = 0; i < 4; i++) {
    s ^= s >> 12n;
    s ^= s << 25n & 0xffffffffffffffffn;
    s ^= s >> 27n;
    acc = (acc << 32n) | (s & 0xffffffffn);
  }
  return min + (acc % range);
}

/** 校验元素是否属于 Z_p* 且落在阶 q 子群中。 */
export function checkGroupElement(el: bigint, gp: GroupParams): string | null {
  if (typeof el !== "bigint") return "元素不是大整数";
  if (el <= 1n) return "元素必须满足 1 < element < p";
  if (el >= gp.p) return "元素必须小于 p（超出范围）";
  if (modPow(el, gp.q, gp.p) !== 1n) {
    return "元素不在阶为 q 的子群中（element^q mod p != 1）";
  }
  return null;
}

/** 完整参数检查：范围、素性、阶整除、生成元阶。 */
export function checkGroupParams(gp: GroupParams): ParamCheckResult {
  const errors: string[] = [];
  const notes: string[] = [];

  if (gp.p < 2n) errors.push("p 必须为大于 1 的素数");
  if (gp.q < 2n) errors.push("q 必须为大于 1 的素数");
  if (errors.length === 0) {
    if (!isProbablePrime(gp.p)) errors.push("p 未通过素性测试");
    if (!isProbablePrime(gp.q)) errors.push("q 未通过素性测试");
    if ((gp.p - 1n) % gp.q !== 0n) errors.push("子群阶 q 必须整除 p-1");

    if (gp.g <= 1n || gp.g >= gp.p) errors.push("生成元 g 必须满足 1 < g < p");
    if (modPow(gp.g, gp.q, gp.p) !== 1n) {
      errors.push("g^q mod p != 1，g 不属于阶 q 子群");
    } else if (gp.g === 1n) {
      errors.push("g 是单位元，不可能是阶 q 生成元");
    } else {
      // 由于 q 为素数，g^q=1 且 g!=1 即说明其阶恰为 q
      notes.push("g^q = 1 且 g != 1；q 为素数，故 g 的阶恰为 q");
    }

    if (gp.unsafeSmall) {
      notes.push(`【不安全】小参数演示集 ${gp.label}：阶仅 ${gp.q}，可被穷举，严禁用于真实认证`);
    } else {
      notes.push(`固定大参数集 ${gp.label}：仅用于展示数学流程，教学实现不保证生产安全`);
    }
  }
  return { ok: errors.length === 0, errors, notes };
}

// ---- 固定参数集 ----

// 小参数：p=607（素），p-1=606=6*101，q=101（素），g=7 的阶为 101
export const SMALL_GROUP: GroupParams = {
  version: "schnorr-teaching/1.0",
  label: "small-unsafe-demo",
  p: 607n,
  q: 101n,
  g: 7n,
  unsafeSmall: true,
};

// 固定大参数：512 位安全素数 p=2q+1，q 256 位，g=3（3 为模 p 二次剩余，阶为 q）
export const LARGE_GROUP: GroupParams = {
  version: "schnorr-teaching/1.0",
  label: "fixed-large-512",
  p: BigInt("0xcd93d2d2adbb7ab23c095aa9d4b4bf841c76c4f63f874de2257092e8be81e25772618b7f5429146720be4658f085d49e6b66e7808f288da367bfb2cd76e1825b"),
  q: BigInt("0x66c9e96956ddbd591e04ad54ea5a5fc20e3b627b1fc3a6f112b849745f40f12bb930c5bfaa148a33905f232c7842ea4f35b373c0479446d1b3dfd966bb70c12d"),
  g: 3n,
  unsafeSmall: false,
};

export const GROUPS: Record<string, GroupParams> = {
  [SMALL_GROUP.label]: SMALL_GROUP,
  [LARGE_GROUP.label]: LARGE_GROUP,
};

export function getGroup(label: string): GroupParams {
  const gp = GROUPS[label];
  if (!gp) throw new Error(`未知参数集: ${label}（可用: ${Object.keys(GROUPS).join(", ")}）`);
  return gp;
}
