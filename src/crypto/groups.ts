/**
 * 群参数定义与参数检查。
 *
 * 参数形式：素数模群 Z_p^* 的一个素数阶 q 子群，生成元为 g。
 * 需要检查：
 *   1. p、q 为素数；
 *   2. q 整除 p-1（子群阶合法）；
 *   3. g 在 [2, p-2] 范围内且 g^q ≡ 1 (mod p)，且 g ≠ 1（确为 q 阶元素）；
 *   4. 群元素取值在 [1, p-1]，且 v^q ≡ 1 (mod p)（属于该子群）。
 *
 * 警告：small 参数仅用于手算演示，完全不安全。
 */

import { isProbablePrime, modPow } from "./math.js";

export interface GroupParams {
  id: string;
  label: string;
  insecure: boolean;
  p: bigint;
  q: bigint;
  g: bigint;
  description: string;
}

export const GROUP_SMALL: GroupParams = {
  id: "small-demo",
  label: "不安全小参数（手算演示，严禁用于任何真实场景）",
  insecure: true,
  // p = 23 是安全素数，q = (p-1)/2 = 11，g = 2 是二次剩余子群生成元。
  p: 23n,
  q: 11n,
  g: 2n,
  description:
    "p=23, q=11, g=2。Z_23^* 中阶为 11 的子群，可纸笔验算，离散对数可被穷举。",
};

export const GROUP_256: GroupParams = {
  id: "fixed-256",
  label: "固定 256 位安全素数参数（教学流程演示，未经标准组织审计）",
  insecure: false,
  p: BigInt("0x182e1f3fc6364bad937ba0cdb21d762be9aeef7e35ede11c70c65b52d9ffe4487"),
  q: BigInt("0xc170f9fe31b25d6c9bdd066d90ebb15f4d777bf1af6f08e38632da96cfff2243"),
  g: 2n,
  description:
    "p=2q+1 为 256 位安全素数（本项目生成），g=2 具有阶 q。位数偏小，仅用于展示数学流程。",
};

export const KNOWN_GROUPS: Record<string, GroupParams> = {
  [GROUP_SMALL.id]: GROUP_SMALL,
  [GROUP_256.id]: GROUP_256,
};

export function getGroup(id: string): GroupParams {
  const group = KNOWN_GROUPS[id];
  if (!group) throw new Error(`未知群参数: ${id}（可选：${Object.keys(KNOWN_GROUPS).join(", ")}）`);
  return group;
}

export interface GroupCheckResult {
  ok: boolean;
  checks: { name: string; pass: boolean; detail: string }[];
}

/** 完整检查群参数；大参数素性测试使用较多轮数。 */
export function checkGroup(group: GroupParams, primeRounds = 24): GroupCheckResult {
  const { p, q, g } = group;
  const checks: GroupCheckResult["checks"] = [];

  checks.push({
    name: "p 是素数",
    pass: isProbablePrime(p, group.insecure ? 10 : primeRounds),
    detail: `p 的位宽为 ${p.toString(2).length} bit`,
  });
  checks.push({
    name: "q 是素数",
    pass: isProbablePrime(q, group.insecure ? 10 : primeRounds),
    detail: `q=${q}`,
  });
  checks.push({
    name: "q 整除 p-1（存在 q 阶子群）",
    pass: (p - 1n) % q === 0n,
    detail: `(p-1) mod q = ${(p - 1n) % q}`,
  });
  checks.push({
    name: "生成元范围 2 <= g <= p-2",
    pass: g >= 2n && g <= p - 2n,
    detail: `g=${g}`,
  });
  checks.push({
    name: "g^q ≡ 1 (mod p) 且 g ≠ 1（g 属于且生成 q 阶子群）",
    pass: g !== 1n && modPow(g, q, p) === 1n,
    detail: `g^q mod p = ${modPow(g, q, p)}`,
  });

  return { ok: checks.every((c) => c.pass), checks };
}

export type ElementScope = "subgroup" | "non-identity";

/**
 * 检查一个元素是否为合法群元素。
 * - subgroup: 必须满足 1 <= v <= p-1 且 v^q ≡ 1；
 * - non-identity: 在 subgroup 基础上拒绝单位元 v=1（防止退化公钥/承诺）。
 */
export function checkGroupElement(
  group: GroupParams,
  v: bigint,
  scope: ElementScope = "subgroup",
): { ok: boolean; reason?: string } {
  const { p, q } = group;
  if (typeof v !== "bigint") return { ok: false, reason: "元素不是整数" };
  if (v < 1n || v > p - 1n) return { ok: false, reason: "元素超出 [1, p-1] 范围" };
  if (modPow(v, q, p) !== 1n) return { ok: false, reason: "元素不在 q 阶子群内（v^q ≠ 1 mod p）" };
  if (scope === "non-identity" && v === 1n) {
    return { ok: false, reason: "拒绝单位元（退化解）" };
  }
  return { ok: true };
}

/** 标量是否在 [0, q-1] 内。 */
export function isScalarInRange(group: GroupParams, x: bigint): boolean {
  return typeof x === "bigint" && x >= 0n && x < group.q;
}

/** 非零标量 [1, q-1]。 */
export function isNonZeroScalar(group: GroupParams, x: bigint): boolean {
  return isScalarInRange(group, x) && x !== 0n;
}
