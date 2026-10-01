// Schnorr 离散对数知识证明核心（自实现，BigInt 模运算）。
//
// 关系：公开 y = g^x mod p，证明者知道 x（不揭示 x）。
// 承诺 t = g^k mod p；挑战 c；响应 s = k - c*x mod q；
// 验证：g^s * y^c mod p == t。
//
// 转录分两类，版本+类型显式区分，禁止混用：
//   interactive  version=schnorr-teaching/1.0  transcriptType=interactive
//   noninteractive Fiat-Shamir transcriptType=fiat-shamir
import { canonical, sha256Bigint, sha256Hex } from "./encoding.js";
import { modPow, modInverse, randomScalar, type RandomSource } from "./bignum.js";
import { checkGroupElement, type GroupParams } from "./params.js";

export const PROTOCOL_VERSION = "schnorr-teaching/1.0";

// TLV tag 分配（固定，避免字段错位）
export const TAGS = {
  version: 1,
  transcriptType: 2,
  groupLabel: 3,
  p: 4,
  q: 5,
  g: 6,
  publicKey: 7,
  commitment: 8,
  context: 9,
  challenge: 10,
  response: 11,
} as const;

export type TranscriptType = "interactive" | "fiat-shamir";

export interface Transcript {
  version: string;
  transcriptType: TranscriptType;
  groupLabel: string;
  context: string;
  publicKey: string; // 十进制 bigint
  commitment: string;
  challenge: string; // 十进制 bigint，[0,q-1]
  response: string; // 十进制 bigint，[0,q-1]
}

export interface ProofArtifacts {
  transcript: Transcript;
  // 以下两个字段为秘密，仅在本地生成时短暂返回；服务端不得持久化、不得出现在导出中
  secretScalar?: string;
  nonce?: string;
}

export function bi(x: string | bigint): bigint {
  return typeof x === "bigint" ? x : BigInt(x);
}

export function dec(x: bigint): string {
  return x.toString(10);
}

/** 校验标量范围 0 <= v < q（挑战允许 0，响应允许 0；私钥/nonce 要求 1..q-1）。 */
export function checkScalar(v: bigint, q: bigint, field: string): string | null {
  if (v < 0n) return `${field} 不能为负`;
  if (v >= q) return `${field} 必须小于子群阶 q`;
  return null;
}

/**
 * Fiat-Shamir 挑战：c = SHA-256(规范编码(版本, 类型, 群, 公钥, 承诺, 上下文)) mod q。
 * 输入采用带长度边界的 TLV，杜绝字符串拼接歧义。
 */
export function fiatShamirChallenge(
  gp: GroupParams,
  publicKey: bigint,
  commitment: bigint,
  context: string
): bigint {
  const data = canonical(
    [TAGS.version, PROTOCOL_VERSION],
    [TAGS.transcriptType, "fiat-shamir"],
    [TAGS.groupLabel, gp.label],
    [TAGS.p, gp.p],
    [TAGS.q, gp.q],
    [TAGS.g, gp.g],
    [TAGS.publicKey, publicKey],
    [TAGS.commitment, commitment],
    [TAGS.context, context]
  );
  return sha256Bigint(data) % gp.q;
}

/**
 * 交互挑战的「挑战信封」哈希（服务端签发挑战时绑定上下文等公开数据）：
 * 服务端自行生成 c ∈ [0,q-1]，这里提供绑定摘要用于审计与防替换。
 */
export function interactiveBindingDigest(
  gp: GroupParams,
  publicKey: bigint,
  commitment: bigint,
  context: string,
  challenge: bigint
): string {
  const data = canonical(
    [TAGS.version, PROTOCOL_VERSION],
    [TAGS.transcriptType, "interactive"],
    [TAGS.groupLabel, gp.label],
    [TAGS.p, gp.p],
    [TAGS.q, gp.q],
    [TAGS.g, gp.g],
    [TAGS.publicKey, publicKey],
    [TAGS.commitment, commitment],
    [TAGS.context, context],
    [TAGS.challenge, challenge]
  );
  return sha256Hex(data);
}

/** 生成密钥对（本地/CLI）。返回秘密标量，服务端不应接收保存。 */
export function generateKeyPair(gp: GroupParams, rand?: RandomSource): { secretScalar: bigint; publicKey: bigint } {
  const x = randomScalar(gp.q, rand);
  return { secretScalar: x, publicKey: modPow(gp.g, x, gp.p) };
}

/** 承诺阶段：生成 nonce k 与 t = g^k mod p。 */
export function commit(gp: GroupParams, rand?: RandomSource): { nonce: bigint; commitment: bigint } {
  const k = randomScalar(gp.q, rand);
  return { nonce: k, commitment: modPow(gp.g, k, gp.p) };
}

/** 响应：s = k - c*x mod q。 */
export function respond(gp: GroupParams, nonce: bigint, challenge: bigint, secretScalar: bigint): bigint {
  return ((nonce - challenge * secretScalar) % gp.q + gp.q) % gp.q;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  checkTrace?: {
    leftGsYc: string;
    rightCommitment: string;
  };
}

/** 组装转录对象（仅公开值）。 */
export function buildTranscript(args: {
  type: TranscriptType;
  gp: GroupParams;
  context: string;
  publicKey: bigint;
  commitment: bigint;
  challenge: bigint;
  response: bigint;
}): Transcript {
  return {
    version: PROTOCOL_VERSION,
    transcriptType: args.type,
    groupLabel: args.gp.label,
    context: args.context,
    publicKey: dec(args.publicKey),
    commitment: dec(args.commitment),
    challenge: dec(args.challenge),
    response: dec(args.response),
  };
}

/**
 * 离线验证一份转录。严格检查：
 * - 版本与类型
 * - 公钥、承诺为合法子群元素
 * - 挑战、响应范围
 * - 方程 g^s * y^c mod p == t
 */
export function verifyTranscript(tr: Transcript, gp: GroupParams, expectedType?: TranscriptType): VerifyResult {
  if (tr.version !== PROTOCOL_VERSION) {
    return { valid: false, reason: `协议版本不匹配: ${tr.version}` };
  }
  if (expectedType && tr.transcriptType !== expectedType) {
    return { valid: false, reason: `转录类型不匹配: 期望 ${expectedType}，实际 ${tr.transcriptType}（禁止混用）` };
  }
  if (tr.transcriptType !== "interactive" && tr.transcriptType !== "fiat-shamir") {
    return { valid: false, reason: `未知转录类型: ${String(tr.transcriptType)}` };
  }
  if (tr.groupLabel !== gp.label) {
    return { valid: false, reason: `参数集不匹配: ${tr.groupLabel} != ${gp.label}` };
  }

  let y: bigint, t: bigint, c: bigint, s: bigint;
  try {
    y = bi(tr.publicKey);
    t = bi(tr.commitment);
    c = bi(tr.challenge);
    s = bi(tr.response);
  } catch {
    return { valid: false, reason: "转录包含无法解析的大整数" };
  }

  const yErr = checkGroupElement(y, gp);
  if (yErr) return { valid: false, reason: `非法公开密钥: ${yErr}` };
  const tErr = checkGroupElement(t, gp);
  if (tErr) return { valid: false, reason: `非法承诺: ${tErr}` };
  const cErr = checkScalar(c, gp.q, "挑战");
  if (cErr) return { valid: false, reason: cErr };
  const sErr = checkScalar(s, gp.q, "响应");
  if (sErr) return { valid: false, reason: sErr };
  if (typeof tr.context !== "string") return { valid: false, reason: "上下文必须为字符串" };

  // Fiat-Shamir 转录必须重算挑战，任何字段被改都会失配
  if (tr.transcriptType === "fiat-shamir") {
    const c2 = fiatShamirChallenge(gp, y, t, tr.context);
    if (c2 !== c) {
      return { valid: false, reason: "Fiat-Shamir 挑战与转录不一致（字段或上下文被改动）" };
    }
  }

  const left = (modPow(gp.g, s, gp.p) * modPow(y, c, gp.p)) % gp.p;
  return {
    valid: left === t,
    reason: left === t ? undefined : "验证方程失败: g^s * y^c mod p != t",
    checkTrace: { leftGsYc: dec(left), rightCommitment: dec(t) },
  };
}

/** 生成完整非交互（Fiat-Shamir）证明。秘密仅随返回值短暂存在。 */
export function proveNonInteractive(
  gp: GroupParams,
  secretScalar: bigint,
  context: string,
  rand?: RandomSource
): ProofArtifacts {
  if (secretScalar <= 0n || secretScalar >= gp.q) throw new Error("私钥必须在 [1,q-1]");
  const { nonce, commitment } = commit(gp, rand);
  const publicKey = modPow(gp.g, secretScalar, gp.p);
  const challenge = fiatShamirChallenge(gp, publicKey, commitment, context);
  const response = respond(gp, nonce, challenge, secretScalar);
  return {
    transcript: buildTranscript({ type: "fiat-shamir", gp, context, publicKey, commitment, challenge, response }),
    secretScalar: dec(secretScalar),
    nonce: dec(nonce),
  };
}

// ---- nonce 重用分析（仅小参数演示）----
// 同一 k（同一承诺 t）、不同挑战 c1 != c2：
//   s1 = k - c1*x, s2 = k - c2*x (mod q)
//   s1 - s2 = (c2 - c1)*x => x = (s1-s2) * (c2-c1)^-1 mod q
export interface NonceReuseResult {
  recovered: boolean;
  secretScalar?: string;
  explanation: string;
}

export function analyzeNonceReuse(
  gp: GroupParams,
  a: { commitment: string; challenge: string; response: string },
  b: { commitment: string; challenge: string; response: string }
): NonceReuseResult {
  const t1 = bi(a.commitment), t2 = bi(b.commitment);
  const c1 = bi(a.challenge), c2 = bi(b.challenge);
  const s1 = bi(a.response), s2 = bi(b.response);

  if (t1 !== t2) {
    return { recovered: false, explanation: "两份转录承诺不同（nonce 不同），不满足重用前提，不进行恢复（合法不同 nonce 不会误报）" };
  }
  if (c1 === c2) {
    return { recovered: false, explanation: "挑战相同：这是重放/重复挑战而非两份不同挑战，无法也不应恢复秘密" };
  }
  const denom = modInverse(((c2 - c1) % gp.q + gp.q) % gp.q, gp.q);
  const x = (((s1 - s2) % gp.q + gp.q) % gp.q) * denom % gp.q;
  return {
    recovered: true,
    secretScalar: dec(x),
    explanation:
      "同一 nonce k 导致 s1-s2=(c2-c1)*x (mod q)，且 c1!=c2 保证逆元存在，" +
      "故 x=(s1-s2)*(c2-c1)^-1 mod q 可恢复私钥。这说明绝不可重用 nonce。",
  };
}


