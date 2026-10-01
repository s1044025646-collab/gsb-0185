/**
 * 固定的可手算样本（基于 small-demo: p=23, q=11, g=2）。
 *
 * 手算依据：
 *   私钥 x=3        => y = 2^3 mod 23 = 8
 *   nonce k=5       => R = 2^5 mod 23 = 32 mod 23 = 9
 *   挑战 c=7        => s = (5 - 7*3) mod 11 = -16 mod 11 = 6
 *   验证：g^s · y^c mod p
 *        2^6 mod 23 = 64 mod 23 = 18
 *        8^7 mod 23：8^2=64=18, 8^4=18^2=324 mod23=2,
 *        8^7=8^4·8^2·8 = 2·18·8 = 288 mod 23 = 12
 *        18·12 = 216 mod 23 = 9 = R  ✓
 *
 * 所有秘密 x、k 只在构造样本时出现于内存，不入库、不入服务日志。
 */

import { GROUP_SMALL } from "./crypto/groups.js";
import {
  INTERACTIVE_KIND,
  FS_KIND,
  PROTOCOL_VERSION,
  proveFiatShamir,
  type InteractiveTranscript,
  type FiatShamirTranscript,
} from "./crypto/schnorr.js";
import { deterministicRandomSource } from "./crypto/math.js";

export const SAMPLE_CONTEXT = "lab-context-alpha";

export interface HandSample {
  name: string;
  description: string;
  transcript: InteractiveTranscript;
}

function interactive(
  context: string,
  y: bigint,
  commitment: bigint,
  challenge: bigint,
  response: bigint,
): InteractiveTranscript {
  return {
    kind: INTERACTIVE_KIND,
    protocolVersion: PROTOCOL_VERSION,
    groupId: GROUP_SMALL.id,
    context,
    y,
    commitment,
    challenge,
    response,
  };
}

/** 可纸笔验算的正确证明（s=6）。 */
export function validHandSample(): HandSample {
  return {
    name: "valid-hand-computable",
    description: "x=3,k=5,c=7 => s=6；g^6·8^7 mod 23 = 9 = R。",
    transcript: interactive(SAMPLE_CONTEXT, 8n, 9n, 7n, 6n),
  };
}

/** 仅把响应 s=6 改为 5，验证方程必然失败。 */
export function tamperedResponseSample(): HandSample {
  return {
    name: "tampered-response",
    description: "与正确样本相同，但响应从 6 被改成 5。",
    transcript: interactive(SAMPLE_CONTEXT, 8n, 9n, 7n, 5n),
  };
}

/** 同样的承诺与挑战，但上下文被替换。 */
export function swappedContextSample(): HandSample {
  return {
    name: "swapped-context",
    description: "数学方程仍成立，但上下文从 lab-context-alpha 替换成 other-context。",
    transcript: interactive("other-context", 8n, 9n, 7n, 6n),
  };
}

/** 正确样本的逐字节副本，用于演示同一挑战的重复提交。 */
export function duplicateChallengeSample(): HandSample {
  return {
    name: "duplicate-challenge",
    description: "与正确样本完全相同：同一挑战第二次提交必须被拒绝。",
    transcript: interactive(SAMPLE_CONTEXT, 8n, 9n, 7n, 6n),
  };
}

/**
 * nonce 重用样本：同一 nonce k=5（R=9），两个不同挑战 c1=7、c2=4。
 *   s1 = (5-7·3) mod 11 = -16 mod 11 = 6
 *   s2 = (5-4·3) mod 11 = -7  mod 11 = 4
 *   x = (s2-s1)·(c1-c2)^-1 mod 11 = (-2)·3^-1 = (-2)·4 = -8 mod 11 = 3 ✓
 */
export function nonceReuseSamples(): {
  first: InteractiveTranscript;
  second: InteractiveTranscript;
  recovered: bigint;
} {
  const first = interactive(SAMPLE_CONTEXT, 8n, 9n, 7n, 6n);
  const second = interactive(SAMPLE_CONTEXT, 8n, 9n, 4n, 4n);
  return { first, second, recovered: 3n };
}

/**
 * 两份不同 nonce 的合法证明：
 *   k1=5 => R1=9, c1=7 => s1=6
 *   k2=8 => R2=2^8 mod23=3, c2=4 => s2=(8-12) mod11=7
 */
export function distinctNonceSamples(): {
  first: InteractiveTranscript;
  second: InteractiveTranscript;
  explanation: string;
} {
  const first = interactive(SAMPLE_CONTEXT, 8n, 9n, 7n, 6n);
  const second = interactive(SAMPLE_CONTEXT, 8n, 3n, 4n, 7n);
  return {
    first,
    second,
    explanation:
      "k 不同 => R 不同（9 与 3）。相减得到 s2-s1=(k2-k1)+(c1-c2)x，含两个未知数 k2-k1 与 x，无法恢复私钥，不得误报。",
  };
}

/** 确定性 Fiat-Shamir 样本（注入确定性随机源，仅供测试/复现，默认运行不使用）。 */
export function deterministicFsSamples(): { valid: FiatShamirTranscript; wrongContext: FiatShamirTranscript } {
  const rng = deterministicRandomSource(Buffer.from([5, 7, 9, 11, 13, 17, 19, 23]));
  const sk = { groupId: GROUP_SMALL.id, x: 3n };
  const valid = proveFiatShamir(GROUP_SMALL, sk, SAMPLE_CONTEXT, rng);
  const wrong = { ...valid, context: "attacker-context" };
  return { valid, wrongContext: wrong };
}

export { FS_KIND, INTERACTIVE_KIND };
