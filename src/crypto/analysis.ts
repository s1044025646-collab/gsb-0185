/**
 * Nonce 重用导致私钥恢复的教学分析。
 *
 * 若证明者两次使用相同 nonce k 但面对不同挑战 c1、c2：
 *   s1 = k - c1·x (mod q)
 *   s2 = k - c2·x (mod q)
 * 两式相减：s2 - s1 = (c1 - c2)·x (mod q)
 *   => x = (s2 - s1) · (c1 - c2)^{-1} (mod q)
 *
 * 恢复成立的前提：
 *   1. 两份转录来自同一密钥（y1 = y2）；
 *   2. 承诺相同（R1 = R2），即 nonce 相同；
 *   3. 挑战不同（c1 ≠ c2，因此 c1-c2 可逆）。
 * 对两份使用不同 nonce 的合法转录（R1 ≠ R2），绝不能误报。
 */

import { modInverse, modPow } from "./math.js";
import type { GroupParams } from "./groups.js";
import type { TranscriptBase } from "./schnorr.js";

export interface NonceReuseResult {
  reuseDetected: boolean;
  reason?: string;
  recoveredX?: bigint;
  publicKeyMatches?: boolean;
  explanation: string;
}

export function analyzeNonceReuse(
  group: GroupParams,
  a: TranscriptBase,
  b: TranscriptBase,
): NonceReuseResult {
  if (a.groupId !== group.id || b.groupId !== group.id) {
    return {
      reuseDetected: false,
      reason: "群参数不一致",
      explanation: "两份转录必须基于同一组群参数才能进行分析。",
    };
  }
  if (a.y !== b.y) {
    return {
      reuseDetected: false,
      reason: "公钥不同",
      explanation: "两份转录对应不同密钥，相减会混合两个未知数，无法恢复单一私钥。",
    };
  }
  if (a.commitment !== b.commitment) {
    return {
      reuseDetected: false,
      reason: "承诺不同（nonce 不同）",
      explanation:
        "R1 ≠ R2，说明两次证明使用了不同 nonce。这是安全的正确用法，不存在可解的线性方程组，不报告重用。",
    };
  }
  if (a.challenge === b.challenge) {
    return {
      reuseDetected: false,
      reason: "挑战相同",
      explanation: "承诺相同但挑战也相同，两份转录重复，方程不提供新信息，无法恢复私钥。",
    };
  }

  const deltaC = (a.challenge - b.challenge + group.q) % group.q;
  const deltaS = (b.response - a.response + group.q) % group.q;
  if (deltaC === 0n) {
    return { reuseDetected: false, reason: "挑战差不可逆", explanation: "c1-c2 ≡ 0 (mod q)，无法求逆。" };
  }
  const recoveredX = (deltaS * modInverse(deltaC, group.q)) % group.q;
  const matches = modPow(group.g, recoveredX, group.p) === a.y;

  return {
    reuseDetected: true,
    recoveredX,
    publicKeyMatches: matches,
    explanation:
      "检测到相同承诺 R 与不同挑战：nonce 被重用。由 s2-s1=(c1-c2)x (mod q)，" +
      "计算 x=(s2-s1)·(c1-c2)^(-1) mod q 即可恢复私钥。" +
      (matches
        ? `恢复值满足 g^x=y，私钥恢复成功：x=${recoveredX}。`
        : "恢复值不满足 g^x=y（转录可能被额外篡改）。"),
  };
}
