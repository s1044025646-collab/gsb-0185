/**
 * Schnorr 离散对数知识证明核心算法（教学实现）。
 *
 * 关系：证明者知道 x 使 y = g^x (mod p)。
 *   承诺：k ← [1,q-1]，R = g^k
 *   挑战：c ← [1,q-1]
 *   响应：s = k - c·x (mod q)
 *   验证：g^s · y^c ≡ R (mod p)
 *
 * 非交互版本使用 Fiat-Shamir：c = H(规范编码(版本, 群, y, R, 上下文))。
 *
 * 本模块不提供任何真实匿名性/不可追踪性保证，私钥 x 不应在任何
 * 常规服务响应、日志或公开转录导出中出现。
 */

import {
  randomScalarInField,
  modPow,
  type RandomSource,
  systemRandomSource,
} from "./math.js";
import {
  checkGroupElement,
  isNonZeroScalar,
  isScalarInRange,
  type GroupParams,
} from "./groups.js";
import { hashFieldsToBigInt, int, text } from "./encoding.js";

export const PROTOCOL_VERSION = "schnorr-zkp-v1";
export const INTERACTIVE_KIND = "interactive";
export const FS_KIND = "noninteractive-fiat-shamir";
const FS_DOMAIN = "SCP1/FIAT_SHAMIR_CHALLENGE";

export interface PublicKey {
  groupId: string;
  y: bigint;
}

export interface SecretKey {
  groupId: string;
  x: bigint;
}

export interface TranscriptBase {
  kind: typeof INTERACTIVE_KIND | typeof FS_KIND;
  protocolVersion: string;
  groupId: string;
  context: string;
  y: bigint;
  commitment: bigint; // R
  challenge: bigint; // c
  response: bigint; // s
}

export interface InteractiveTranscript extends TranscriptBase {
  kind: typeof INTERACTIVE_KIND;
  /** 服务端签发的一次性挑战标识；交互式转录必须可由该挑战记录背书。 */
  challengeId?: string;
}

export interface FiatShamirTranscript extends TranscriptBase {
  kind: typeof FS_KIND;
}

export function generateSecretKey(group: GroupParams, rng: RandomSource = systemRandomSource): SecretKey {
  return { groupId: group.id, x: randomScalarInField(group.q, rng) };
}

export function publicKeyFromSecret(group: GroupParams, sk: SecretKey): PublicKey {
  if (sk.groupId !== group.id) throw new Error("密钥与群参数不匹配");
  if (!isNonZeroScalar(group, sk.x)) throw new Error("非法私钥标量");
  return { groupId: group.id, y: modPow(group.g, sk.x, group.p) };
}

/** 允许显式输入私钥（CLI 本地使用），会做范围检查。 */
export function parseSecretKey(group: GroupParams, xInput: bigint): SecretKey {
  if (!isNonZeroScalar(group, xInput)) {
    throw new Error("私钥必须是 [1, q-1] 内的非零整数");
  }
  return { groupId: group.id, x: xInput };
}

export interface Commitment {
  nonce: bigint; // k，秘密，禁止默认持久化
  commitment: bigint; // R
}

export function commit(group: GroupParams, rng: RandomSource = systemRandomSource): Commitment {
  const nonce = randomScalarInField(group.q, rng);
  return { nonce, commitment: modPow(group.g, nonce, group.p) };
}

/** 显式指定 nonce（仅用于 nonce 重用分析/可复现实验）。 */
export function commitWithNonce(group: GroupParams, nonce: bigint): Commitment {
  if (!isNonZeroScalar(group, nonce)) throw new Error("nonce 必须是 [1, q-1] 内的非零整数");
  return { nonce, commitment: modPow(group.g, nonce, group.p) };
}

export function respond(group: GroupParams, sk: SecretKey, nonce: bigint, challenge: bigint): bigint {
  if (sk.groupId !== group.id) throw new Error("私钥与群参数不匹配");
  if (!isNonZeroScalar(group, nonce)) throw new Error("非法 nonce");
  if (!isNonZeroScalar(group, challenge)) throw new Error("挑战必须是 [1, q-1] 内的非零整数");
  if (!isNonZeroScalar(group, sk.x)) throw new Error("非法私钥");
  const raw = (nonce - challenge * sk.x) % group.q;
  return raw < 0n ? raw + group.q : raw;
}

function challengeInput(group: GroupParams, context: string, y: bigint, commitment: bigint) {
  return [
    text(PROTOCOL_VERSION),
    text(group.id),
    int(group.p),
    int(group.q),
    int(group.g),
    int(y),
    int(commitment),
    text(context),
  ];
}

/** Fiat-Shamir 挑战；带内部计数器以极小概率避开 0 退化值。 */
export function fiatShamirChallenge(
  group: GroupParams,
  context: string,
  y: bigint,
  commitment: bigint,
): bigint {
  const base = challengeInput(group, context, y, commitment);
  for (let counter = 0n; counter < 1000n; counter++) {
    const c = hashFieldsToBigInt(FS_DOMAIN, [...base, int(counter)]) % group.q;
    if (c !== 0n) return c;
  }
  throw new Error("无法生成非零 Fiat-Shamir 挑战");
}

export function proveFiatShamir(
  group: GroupParams,
  sk: SecretKey,
  context: string,
  rng: RandomSource = systemRandomSource,
): FiatShamirTranscript {
  const { nonce, commitment } = commit(group, rng);
  const y = publicKeyFromSecret(group, sk).y;
  const challenge = fiatShamirChallenge(group, context, y, commitment);
  return {
    kind: FS_KIND,
    protocolVersion: PROTOCOL_VERSION,
    groupId: group.id,
    context,
    y,
    commitment,
    challenge,
    response: respond(group, sk, nonce, challenge),
  };
}

/** 交互式流程中由证明者组装最终转录。 */
export function buildInteractiveTranscript(
  group: GroupParams,
  sk: SecretKey,
  context: string,
  commitmentObj: Commitment,
  challenge: bigint,
): InteractiveTranscript {
  const y = publicKeyFromSecret(group, sk).y;
  return {
    kind: INTERACTIVE_KIND,
    protocolVersion: PROTOCOL_VERSION,
    groupId: group.id,
    context,
    y,
    commitment: commitmentObj.commitment,
    challenge,
    response: respond(group, sk, commitmentObj.nonce, challenge),
  };
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

function verifyCommon(
  group: GroupParams,
  t: TranscriptBase,
  expectedKind: string,
  expectedContext?: string,
): VerifyResult {
  if (t.kind !== expectedKind) {
    return { valid: false, reason: `转录类型不匹配：期望 ${expectedKind}，实际 ${t.kind}（禁止混用）` };
  }
  if (t.protocolVersion !== PROTOCOL_VERSION) {
    return { valid: false, reason: `协议版本不匹配：期望 ${PROTOCOL_VERSION}` };
  }
  if (t.groupId !== group.id) return { valid: false, reason: "群参数 ID 不匹配" };
  if (typeof t.context !== "string" || t.context.length === 0 || t.context.length > 1024) {
    return { valid: false, reason: "上下文必须为 1..1024 字符的字符串" };
  }
  if (expectedContext !== undefined && t.context !== expectedContext) {
    return { valid: false, reason: "上下文不匹配（疑似跨上下文复用转录）" };
  }
  let check = checkGroupElement(group, t.y, "non-identity");
  if (!check.ok) return { valid: false, reason: `非法公钥：${check.reason}` };
  check = checkGroupElement(group, t.commitment, "non-identity");
  if (!check.ok) return { valid: false, reason: `非法承诺：${check.reason}` };
  if (!isNonZeroScalar(group, t.challenge)) return { valid: false, reason: "挑战超出 [1,q-1] 范围" };
  if (!isScalarInRange(group, t.response)) return { valid: false, reason: "响应超出 [0,q-1] 范围" };
  return { valid: true };
}

/** 验证交互式转录；可选绑定期望上下文。 */
export function verifyInteractive(
  group: GroupParams,
  t: InteractiveTranscript,
  expectedContext?: string,
): VerifyResult {
  const common = verifyCommon(group, t, INTERACTIVE_KIND, expectedContext);
  if (!common.valid) return common;
  const lhs = (modPow(group.g, t.response, group.p) * modPow(t.y, t.challenge, group.p)) % group.p;
  if (lhs !== t.commitment) return { valid: false, reason: "验证方程不成立：g^s·y^c ≠ R" };
  return { valid: true };
}

/** 验证 Fiat-Shamir 转录：重新计算挑战并检查方程。 */
export function verifyFiatShamir(
  group: GroupParams,
  t: FiatShamirTranscript,
  expectedContext?: string,
): VerifyResult {
  const common = verifyCommon(group, t, FS_KIND, expectedContext);
  if (!common.valid) return common;
  const recomputed = fiatShamirChallenge(group, t.context, t.y, t.commitment);
  if (recomputed !== t.challenge) {
    return { valid: false, reason: "挑战与规范哈希重算结果不一致（承诺/上下文/公钥被篡改）" };
  }
  const lhs = (modPow(group.g, t.response, group.p) * modPow(t.y, t.challenge, group.p)) % group.p;
  if (lhs !== t.commitment) return { valid: false, reason: "验证方程不成立：g^s·y^c ≠ R" };
  return { valid: true };
}

export function verifyTranscript(
  group: GroupParams,
  t: TranscriptBase,
  expectedContext?: string,
): VerifyResult {
  return t.kind === FS_KIND
    ? verifyFiatShamir(group, t as FiatShamirTranscript, expectedContext)
    : verifyInteractive(group, t as InteractiveTranscript, expectedContext);
}
