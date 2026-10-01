// 业务服务层：参数检查、挑战签发（一次消费/TTL/上下文绑定）、提交响应、离线验证、导入导出。
import { modPow, randomBigIntBetween } from "./bignum.js";
import { getGroup, checkGroupParams, checkGroupElement, type GroupParams } from "./params.js";
import {
  bi, buildTranscript, commit, dec, generateKeyPair, interactiveBindingDigest,
  proveNonInteractive, respond, verifyTranscript, analyzeNonceReuse,
  type ProofArtifacts, type Transcript, type VerifyResult,
} from "./proof.js";
import { initDefaultStore, type AppDB, type StoredChallenge } from "./db.js";

export const DEFAULT_TTL_MS = 5 * 60 * 1000;

export interface IssueChallengeInput {
  group: string;
  context: string;
  publicKey: string;
  commitment: string;
  ttlMs?: number;
}

export interface SubmitResponseInput {
  challengeId: string;
  response: string;
  /** 可选：提交时携带期望上下文，服务端会与签发记录比对，拒绝跨上下文复用 */
  context?: string;
}

export class ServiceError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export class SchnorrService {
  constructor(public store: AppDB) {}

  static open(dbFile: string): SchnorrService {
    return new SchnorrService(initDefaultStore(dbFile));
  }

  close(): void {
    this.store.db.close();
  }

  listGroups() {
    return this.store.listGroups();
  }

  checkGroup(label: string) {
    const gp = getGroup(label);
    return checkGroupParams(gp);
  }

  /** 本地生成演示密钥对。注意：私钥只返回给本地 CLI，本服务不落库、不写日志。 */
  localDemoKeyPair(label: string): { group: string; publicKey: string; secretScalar: string } {
    const gp = getGroup(label);
    const { secretScalar, publicKey } = generateKeyPair(gp);
    return { group: gp.label, publicKey: dec(publicKey), secretScalar: dec(secretScalar) };
  }

  /** 本地生成演示证明（含秘密字段）。调用方负责只在本地展示，秘密不进入存储/导出。 */
  localDemoProof(label: string, secretScalar: string, context: string): ProofArtifacts {
    const gp = getGroup(label);
    return proveNonInteractive(gp, bi(secretScalar), context);
  }

  issueChallenge(input: IssueChallengeInput, opts: { ttlMs?: number } = {}): {
    challengeId: string;
    challenge: string;
    expiresAt: string;
    bindingDigest: string;
  } {
    if (!input.context || typeof input.context !== "string") {
      throw new ServiceError(400, "context 必须为非空字符串（用于域分离，防跨上下文复用）");
    }
    if (input.context.length > 1024) throw new ServiceError(400, "context 过长（>1024）");
    const gp = getGroup(input.group);

    let y: bigint, t: bigint;
    try { y = bi(input.publicKey); } catch { throw new ServiceError(400, "publicKey 非法"); }
    try { t = bi(input.commitment); } catch { throw new ServiceError(400, "commitment 非法"); }

    const yErr = checkGroupElement(y, gp);
    if (yErr) throw new ServiceError(400, `非法公开密钥: ${yErr}`);
    const tErr = checkGroupElement(t, gp);
    if (tErr) throw new ServiceError(400, `非法承诺: ${tErr}`);

    // 服务端签发随机挑战 c ∈ [0,q-1]
    const c = randomBigIntBetween(0n, gp.q - 1n);
    const ttl = input.ttlMs ?? opts.ttlMs ?? DEFAULT_TTL_MS;
    const expiresAt = new Date(Date.now() + ttl).toISOString();
    const row = this.store.createChallenge({
      groupLabel: gp.label,
      context: input.context,
      publicKey: dec(y),
      commitment: dec(t),
      challenge: dec(c),
      expiresAt,
    });
    return {
      challengeId: row.id,
      challenge: dec(c),
      expiresAt,
      bindingDigest: interactiveBindingDigest(gp, y, t, input.context, c),
    };
  }

  /**
   * 提交交互式响应。
   * 原子消费：过期拒绝、重复/并发提交最多成功一次；记录验证方程结果与验证历史。
   */
  submitResponse(input: SubmitResponseInput): {
    challengeId: string;
    status: string;
    valid: boolean;
    reason: string | null;
    transcriptId: string | null;
    trace: VerifyResult["checkTrace"];
  } {
    const row: StoredChallenge | null = this.store.getChallenge(input.challengeId);
    if (!row) throw new ServiceError(404, "挑战不存在");
    this.store.markExpiredPending(new Date());
    const fresh = this.store.getChallenge(input.challengeId);
    if (fresh && fresh.status === "expired") {
      this.recordVerification(null, {
        kind: "interactive", group_label: row.group_label, context: row.context,
        valid: false, reason: "挑战已过期", detail: null,
      });
      throw new ServiceError(410, "挑战已过期");
    }
    if (fresh && fresh.status === "consumed") {
      this.recordVerification(null, {
        kind: "interactive", group_label: row.group_label, context: row.context,
        valid: false, reason: "挑战已被消费（防重放）", detail: null,
      });
      throw new ServiceError(409, "挑战已被消费，禁止重复提交");
    }

    if (input.context !== undefined && input.context !== row.context) {
      this.recordVerification(null, {
        kind: "interactive", group_label: row.group_label, context: row.context,
        valid: false, reason: "跨上下文复用被拒绝", detail: null,
      });
      throw new ServiceError(400, `上下文不匹配：该挑战绑定上下文，不能在其他上下文复用`);
    }

    const gp = getGroup(row.group_label);
    let s: bigint;
    try { s = bi(input.response); } catch { throw new ServiceError(400, "response 非法"); }
    if (s < 0n || s >= gp.q) throw new ServiceError(400, "响应超出 [0,q-1] 范围");

    const tr = buildTranscript({
      type: "interactive",
      gp,
      context: row.context,
      publicKey: bi(row.public_key),
      commitment: bi(row.commitment),
      challenge: bi(row.challenge),
      response: s,
    });
    const result = verifyTranscript(tr, gp, "interactive");

    // 原子消费：无论方程是否成立，挑战都被消费（一次性），并发下只有一个请求进入成功路径
    const consumed = this.store.consumeChallenge(
      row.id, dec(s), result.valid, result.reason ?? null
    );
    if (consumed === "used") throw new ServiceError(409, "并发提交：该挑战已被另一请求消费");
    if (consumed === "expired") throw new ServiceError(410, "挑战已过期");
    if (consumed === "missing") throw new ServiceError(404, "挑战不存在");

    // 仅公开转录入库（无秘密、无 nonce）
    let transcriptId: string | null = null;
    if (result.valid) {
      const saved = this.store.insertTranscript({
        kind: "interactive",
        groupLabel: gp.label,
        context: tr.context,
        publicKey: tr.publicKey,
        commitment: tr.commitment,
        challenge: tr.challenge,
        response: tr.response,
        source: "api",
      });
      transcriptId = saved.id;
    }
    this.recordVerification(transcriptId, {
      kind: "interactive", group_label: gp.label, context: row.context,
      valid: result.valid, reason: result.reason ?? null,
      detail: JSON.stringify(result.checkTrace ?? null),
    });

    return {
      challengeId: row.id,
      status: consumed.status,
      valid: result.valid,
      reason: result.reason ?? null,
      transcriptId,
      trace: result.checkTrace,
    };
  }

  /** 离线验证任意转录（交互/非交互均可，类型不可混用）。 */
  offlineVerify(tr: Transcript): VerifyResult & { verificationId: string } {
    const gp = getGroup(tr.groupLabel);
    const expected = tr.transcriptType === "fiat-shamir" ? "fiat-shamir" : "interactive";
    const result = verifyTranscript(tr, gp, expected);
    const saved = this.store.insertTranscript({
      kind: tr.transcriptType === "fiat-shamir" ? "fiat-shamir" : "interactive",
      groupLabel: gp.label,
      context: tr.context,
      publicKey: tr.publicKey,
      commitment: tr.commitment,
      challenge: tr.challenge,
      response: tr.response,
      source: "import",
    });
    const v = this.recordVerification(saved.id, {
      kind: expected, group_label: gp.label, context: tr.context,
      valid: result.valid, reason: result.reason ?? null,
      detail: JSON.stringify(result.checkTrace ?? null),
    });
    return { ...result, verificationId: v.id };
  }

  /** 保存非交互证明的公开转录（用于导出/演示）。秘密字段一律剥离。 */
  saveNonInteractive(tr: Transcript, source: "api" | "cli" = "cli"): string {
    const gp = getGroup(tr.groupLabel);
    const result = verifyTranscript(tr, gp, "fiat-shamir");
    if (!result.valid) throw new ServiceError(400, `转录校验失败，拒绝保存: ${result.reason ?? ""}`);
    const saved = this.store.insertTranscript({
      kind: "fiat-shamir",
      groupLabel: gp.label,
      context: tr.context,
      publicKey: tr.publicKey,
      commitment: tr.commitment,
      challenge: tr.challenge,
      response: tr.response,
      source,
    });
    this.recordVerification(saved.id, {
      kind: "fiat-shamir", group_label: gp.label, context: tr.context,
      valid: true, reason: null, detail: JSON.stringify(result.checkTrace ?? null),
    });
    return saved.id;
  }

  analyzeNonceReuseSamples(label: string): {
    group: string;
    sameNonce: { c1: string; s1: string; c2: string; s2: string; commitment: string; recoveredSecret: string; explanation: string };
    differentNonce: { recovered: boolean; explanation: string };
  } {
    const gp = getGroup(label);
    if (!gp.unsafeSmall) {
      throw new ServiceError(400, "nonce 重用恢复分析仅允许在明确标注的不安全小参数集上运行");
    }
    const x = 7n; // 教学固定私钥（小参数），公开用于演算
    const y = modPow(gp.g, x, gp.p);
    const k = 13n; // 教学固定 nonce
    const t = modPow(gp.g, k, gp.p);
    const c1 = 5n, c2 = 42n;
    const s1 = respond(gp, k, c1, x);
    const s2 = respond(gp, k, c2, x);
    const reuse = analyzeNonceReuse(
      gp,
      { commitment: dec(t), challenge: dec(c1), response: dec(s1) },
      { commitment: dec(t), challenge: dec(c2), response: dec(s2) }
    );

    // 合法两份不同 nonce 转录：不得误报
    const k2 = 29n;
    const t2 = modPow(gp.g, k2, gp.p);
    const s1b = respond(gp, k, c1, x);
    const s2b = respond(gp, k2, c2, x);
    const different = analyzeNonceReuse(
      gp,
      { commitment: dec(t), challenge: dec(c1), response: dec(s1b) },
      { commitment: dec(t2), challenge: dec(c2), response: dec(s2b) }
    );

    void y;
    return {
      group: gp.label,
      sameNonce: {
        c1: dec(c1), s1: dec(s1), c2: dec(c2), s2: dec(s2),
        commitment: dec(t),
        recoveredSecret: reuse.secretScalar ?? "",
        explanation: reuse.explanation,
      },
      differentNonce: { recovered: different.recovered, explanation: different.explanation },
    };
  }

  private recordVerification(transcriptId: string | null, v: {
    kind: string; group_label: string; context: string;
    valid: boolean; reason: string | null; detail: string | null;
  }) {
    return this.store.insertVerification({ transcript_id: transcriptId, ...v, valid: v.valid ? 1 : 0 });
  }

  listTranscripts() { return this.store.listTranscripts(); }
  listVerifications() { return this.store.listVerifications(); }
  listChallenges() { return this.store.listChallenges(); }

  /** 导出全部公开转录（绝不含私钥/nonce）。 */
  exportPublic(): { exportedAt: string; transcripts: unknown[]; verifications: unknown[] } {
    return {
      exportedAt: new Date().toISOString(),
      transcripts: this.store.listTranscripts(),
      verifications: this.store.listVerifications(),
    };
  }
}





