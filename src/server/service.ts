/**
 * 服务层：挑战签发、一次性消费、转录验证、导入导出。
 */

import type { DatabaseSync } from "node:sqlite";
import { randomScalarInField } from "../crypto/math.js";
import {
  checkGroup,
  checkGroupElement,
  getGroup,
  isScalarInRange,
  type GroupParams,
} from "../crypto/groups.js";
import {
  INTERACTIVE_KIND,
  FS_KIND,
  PROTOCOL_VERSION,
  verifyInteractive,
  verifyFiatShamir,
  type InteractiveTranscript,
  type FiatShamirTranscript,
  type TranscriptBase,
} from "../crypto/schnorr.js";
import {
  consumeChallenge,
  exportPublicData,
  getChallenge,
  insertChallenge,
  insertTranscript,
  insertVerification,
  listTranscripts,
  listVerifications,
  markExpiredChallenges,
  type ChallengeRow,
} from "./db.js";

export const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;

export interface IssueChallengeInput {
  groupId: string;
  context: string;
  y: bigint;
  commitment: bigint;
  ttlMs?: number;
}

export interface IssueChallengeResult {
  challengeId: string;
  challenge: bigint;
  expiresAt: number;
}

export function issueChallenge(db: DatabaseSync, input: IssueChallengeInput): IssueChallengeResult {
  const group = getGroup(input.groupId);
  validateContext(input.context);
  let check = checkGroupElement(group, input.y, "non-identity");
  if (!check.ok) throw new ValidationError(`非法公钥：${check.reason}`);
  check = checkGroupElement(group, input.commitment, "non-identity");
  if (!check.ok) throw new ValidationError(`非法承诺：${check.reason}`);

  const ttl = input.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 60 * 60 * 1000) {
    throw new ValidationError("ttlMs 必须在 1..3600000 毫秒之间");
  }
  const challenge = randomScalarInField(group.q);
  const expiresAt = Date.now() + ttl;
  const row = insertChallenge(db, {
    group_id: group.id,
    context: input.context,
    y: input.y.toString(),
    commitment: input.commitment.toString(),
    challenge: challenge.toString(),
    expires_at: expiresAt,
  });
  return { challengeId: row.id, challenge, expiresAt: row.expires_at };
}

export interface SubmitResponseInput {
  challengeId: string;
  response: bigint;
}

export interface SubmitResponseResult {
  valid: boolean;
  reason?: string;
  transcriptId?: string;
  challenge: {
    id: string;
    status: string;
    expiresAt: number;
    consumedAt: number | null;
  };
}

/**
 * 提交交互式响应：
 * 挑战必须存在、属于该承诺/公钥/上下文、未过期且只能成功消费一次。
 */
export function submitInteractiveResponse(db: DatabaseSync, input: SubmitResponseInput): SubmitResponseResult {
  markExpiredChallenges(db);
  const row = getChallenge(db, input.challengeId);
  if (!row) throw new NotFoundError("挑战不存在");

  const group = getGroup(row.group_id);
  if (!isScalarInRange(group, input.response)) {
    // 非法输入本身不消费挑战；记录一次失败验证。
    insertVerification(db, {
      transcript_id: null,
      challenge_id: row.id,
      kind: INTERACTIVE_KIND,
      group_id: group.id,
      context: row.context,
      valid: 0,
      reason: "响应超出 [0,q-1] 范围",
    });
    throw new ValidationError("响应超出 [0,q-1] 范围");
  }

  const consume = consumeChallenge(db, row.id);
  if (consume.outcome === "not-found") throw new NotFoundError("挑战不存在");
  if (consume.outcome === "already-consumed") {
    insertVerification(db, {
      transcript_id: null,
      challenge_id: row.id,
      kind: INTERACTIVE_KIND,
      group_id: group.id,
      context: row.context,
      valid: 0,
      reason: "挑战已被消费（重复提交）",
    });
    return {
      valid: false,
      reason: "挑战已被消费，重复提交被拒绝",
      challenge: challengeView(consume.row),
    };
  }
  if (consume.outcome === "expired") {
    insertVerification(db, {
      transcript_id: null,
      challenge_id: row.id,
      kind: INTERACTIVE_KIND,
      group_id: group.id,
      context: row.context,
      valid: 0,
      reason: "挑战已过期",
    });
    return { valid: false, reason: "挑战已过期", challenge: challengeView(consume.row) };
  }

  const transcript: InteractiveTranscript = {
    kind: INTERACTIVE_KIND,
    protocolVersion: PROTOCOL_VERSION,
    groupId: group.id,
    context: row.context,
    y: BigInt(row.y),
    commitment: BigInt(row.commitment),
    challenge: BigInt(row.challenge),
    response: input.response,
  };
  const result = verifyInteractive(group, transcript, row.context);
  const saved = insertTranscript(db, {
    kind: INTERACTIVE_KIND,
    group_id: group.id,
    context: row.context,
    y: row.y,
    commitment: row.commitment,
    challenge: row.challenge,
    response: input.response.toString(),
    transcript_json: JSON.stringify(transcriptJson(transcript), null, 0),
  });
  insertVerification(db, {
    transcript_id: saved.id,
    challenge_id: row.id,
    kind: INTERACTIVE_KIND,
    group_id: group.id,
    context: row.context,
    valid: result.valid ? 1 : 0,
    reason: result.reason ?? null,
  });
  return {
    valid: result.valid,
    reason: result.reason,
    transcriptId: saved.id,
    challenge: challengeView(consume.row),
  };
}

export interface VerifyImportInput {
  transcript: unknown;
  expectedContext?: string;
}

/** 离线/导入验证：接受任意转录 JSON，重新检查全部条件（不依赖签发记录）。 */
export function verifyImportedTranscript(db: DatabaseSync, input: VerifyImportInput) {
  const parsed = parseTranscriptJson(input.transcript);
  const group = getGroup(parsed.groupId);
  const statedKind = (input.transcript as { kind?: unknown })?.kind;
  if (statedKind !== parsed.kind || (parsed.kind !== INTERACTIVE_KIND && parsed.kind !== FS_KIND)) {
    throw new ValidationError("转录类型字段缺失或非法");
  }
  let result;
  if (parsed.kind === FS_KIND) {
    result = verifyFiatShamir(group, parsed as FiatShamirTranscript, input.expectedContext ?? parsed.context);
  } else {
    // 交互式转录通过 /api/verify 导入时，必须提供服务端一次性挑战记录进行背书；
    // 防止把非交互转录的字段重新标注成交互式来通过验证。
    const challengeId = (input.transcript as { challengeId?: unknown })?.challengeId;
    if (typeof challengeId !== "string" || challengeId.length === 0) {
      throw new ValidationError("交互式转录必须携带服务端签发的 challengeId（请使用提交接口）");
    }
    const row = getChallenge(db, challengeId);
    if (!row) throw new ValidationError("challengeId 不存在");
    if (
      row.group_id !== group.id ||
      row.context !== parsed.context ||
      row.y !== parsed.y.toString() ||
      row.commitment !== parsed.commitment.toString() ||
      row.challenge !== parsed.challenge.toString()
    ) {
      throw new ValidationError("交互式转录与签发的挑战记录不一致（疑似类型/字段混用）");
    }
    result = verifyInteractive(group, parsed as InteractiveTranscript, input.expectedContext ?? parsed.context);
  }

  let transcriptId: string | null = null;
  // 仅保存非交互转录（交互转录的归属应由一次性挑战记录证明），避免无绑定复制品入库。
  const saved = insertTranscript(db, {
    kind: parsed.kind,
    group_id: group.id,
    context: parsed.context,
    y: parsed.y.toString(),
    commitment: parsed.commitment.toString(),
    challenge: parsed.challenge.toString(),
    response: parsed.response.toString(),
    transcript_json: JSON.stringify(transcriptJson(parsed)),
  });
  transcriptId = saved.id;
  insertVerification(db, {
    transcript_id: transcriptId,
    challenge_id: null,
    kind: parsed.kind,
    group_id: group.id,
    context: parsed.context,
    valid: result.valid ? 1 : 0,
    reason: result.reason ?? null,
  });
  return {
    valid: result.valid,
    reason: result.reason ?? null,
    kind: parsed.kind,
    groupId: group.id,
    context: parsed.context,
    transcriptId,
  };
}

export function groupCheckInfo(groupId: string) {
  const group = getGroup(groupId);
  return {
    groupId: group.id,
    label: group.label,
    insecure: group.insecure,
    ...checkGroup(group),
  };
}

export function getPublicData(db: DatabaseSync) {
  return exportPublicData(db);
}

export function getTranscripts(db: DatabaseSync, limit: number) {
  return listTranscripts(db, limit);
}

export function getVerifications(db: DatabaseSync, limit: number) {
  return listVerifications(db, limit);
}

function challengeView(row: ChallengeRow) {
  return { id: row.id, status: row.status, expiresAt: row.expires_at, consumedAt: row.consumed_at };
}

function validateContext(context: unknown): asserts context is string {
  if (typeof context !== "string" || context.length === 0 || context.length > 1024) {
    throw new ValidationError("context 必须是 1..1024 字符的字符串");
  }
}

export class ValidationError extends Error {}
export class NotFoundError extends Error {}

export function transcriptJson(t: TranscriptBase) {
  return {
    kind: t.kind,
    protocolVersion: t.protocolVersion,
    groupId: t.groupId,
    context: t.context,
    y: t.y.toString(),
    commitment: t.commitment.toString(),
    challenge: t.challenge.toString(),
    response: t.response.toString(),
  };
}

export function parseTranscriptJson(raw: unknown): TranscriptBase {
  if (typeof raw !== "object" || raw === null) throw new ValidationError("转录必须是 JSON 对象");
  const obj = raw as Record<string, unknown>;
  if (obj.protocolVersion !== PROTOCOL_VERSION) {
    throw new ValidationError(`protocolVersion 必须为 ${PROTOCOL_VERSION}`);
  }
  if (obj.kind !== INTERACTIVE_KIND && obj.kind !== FS_KIND) {
    throw new ValidationError(`kind 必须是 ${INTERACTIVE_KIND} 或 ${FS_KIND}`);
  }
  const required = ["groupId", "context", "y", "commitment", "challenge", "response"] as const;
  for (const key of required) {
    if (typeof obj[key] !== "string") throw new ValidationError(`字段 ${key} 必须是十进制整数字符串`);
  }
  const big = (v: unknown): bigint => {
    try {
      if (typeof v !== "string" || !/^[0-9]+$/.test(v)) throw new Error();
      return BigInt(v);
    } catch {
      throw new ValidationError("大整数字段必须是十进制数字字符串");
    }
  };
  return {
    kind: obj.kind,
    protocolVersion: PROTOCOL_VERSION,
    groupId: obj.groupId as string,
    context: obj.context as string,
    y: big(obj.y),
    commitment: big(obj.commitment),
    challenge: big(obj.challenge),
    response: big(obj.response),
  };
}
