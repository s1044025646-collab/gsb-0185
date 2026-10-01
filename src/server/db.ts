/**
 * SQLite 持久化层（Node 内置 node:sqlite，同步 API）。
 *
 * 仅保存公开信息：
 *   - 群参数
 *   - 待消费/已消费挑战（承诺、挑战、上下文、状态、过期时间）
 *   - 公开证明转录（JSON，不含私钥/nonce）
 *   - 验证记录
 *
 * 私钥 x 与承诺 nonce k 永不写入数据库或日志。
 */

import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { KNOWN_GROUPS } from "../crypto/groups.js";

export type ChallengeStatus = "pending" | "consumed" | "expired";
export type TranscriptKind = "interactive" | "noninteractive-fiat-shamir";

export interface ChallengeRow {
  id: string;
  group_id: string;
  context: string;
  y: string;
  commitment: string;
  challenge: string;
  status: ChallengeStatus;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}

export interface TranscriptRow {
  id: string;
  kind: TranscriptKind;
  group_id: string;
  context: string;
  y: string;
  commitment: string;
  challenge: string;
  response: string;
  transcript_json: string;
  created_at: number;
}

export interface VerificationRow {
  id: string;
  transcript_id: string | null;
  challenge_id: string | null;
  kind: TranscriptKind;
  group_id: string;
  context: string;
  valid: 0 | 1;
  reason: string | null;
  created_at: number;
}

export function openDatabase(path: string): DatabaseSync {
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA busy_timeout = 5000;");
  migrate(db);
  seedGroups(db);
  return db;
}

function migrate(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      insecure INTEGER NOT NULL,
      p TEXT NOT NULL,
      q TEXT NOT NULL,
      g TEXT NOT NULL,
      description TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      group_id TEXT NOT NULL REFERENCES groups(id),
      context TEXT NOT NULL,
      y TEXT NOT NULL,
      commitment TEXT NOT NULL,
      challenge TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending','consumed','expired')),
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS transcripts (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('interactive','noninteractive-fiat-shamir')),
      group_id TEXT NOT NULL REFERENCES groups(id),
      context TEXT NOT NULL,
      y TEXT NOT NULL,
      commitment TEXT NOT NULL,
      challenge TEXT NOT NULL,
      response TEXT NOT NULL,
      transcript_json TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS verifications (
      id TEXT PRIMARY KEY,
      transcript_id TEXT REFERENCES transcripts(id),
      challenge_id TEXT REFERENCES challenges(id),
      kind TEXT NOT NULL,
      group_id TEXT NOT NULL,
      context TEXT NOT NULL,
      valid INTEGER NOT NULL,
      reason TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_challenges_status ON challenges(status);
    CREATE INDEX IF NOT EXISTS idx_verifications_created ON verifications(created_at);
  `);
}

function seedGroups(db: DatabaseSync): void {
  const stmt = db.prepare(
    `INSERT OR IGNORE INTO groups (id, label, insecure, p, q, g, description)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const group of Object.values(KNOWN_GROUPS)) {
    stmt.run(group.id, group.label, group.insecure ? 1 : 0, group.p.toString(), group.q.toString(), group.g.toString(), group.description);
  }
}

export function listGroups(db: DatabaseSync) {
  return db.prepare("SELECT id, label, insecure, p, q, g, description FROM groups ORDER BY insecure, id").all() as Array<{
    id: string;
    label: string;
    insecure: number;
    p: string;
    q: string;
    g: string;
    description: string;
  }>;
}

function newId(prefix: string): string {
  return prefix + "_" + randomBytes(12).toString("hex");
}

export function insertChallenge(
  db: DatabaseSync,
  data: Omit<ChallengeRow, "id" | "status" | "created_at" | "consumed_at">,
): ChallengeRow {
  const id = newId("chl");
  const now = Date.now();
  db.prepare(
    `INSERT INTO challenges (id, group_id, context, y, commitment, challenge, status, created_at, expires_at, consumed_at)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL)`,
  ).run(id, data.group_id, data.context, data.y, data.commitment, data.challenge, now, data.expires_at);
  return getChallenge(db, id)!;
}

export function getChallenge(db: DatabaseSync, id: string): ChallengeRow | null {
  const row = db.prepare("SELECT * FROM challenges WHERE id = ?").get(id) as unknown as ChallengeRow | undefined;
  return row ?? null;
}

export type ConsumeOutcome =
  | { outcome: "consumed"; row: ChallengeRow }
  | { outcome: "already-consumed"; row: ChallengeRow }
  | { outcome: "expired"; row: ChallengeRow }
  | { outcome: "not-found" };

/**
 * 在一个 IMMEDIATE 事务中尝试消费挑战。
 * 并发提交时只有一个事务能把 pending 改为 consumed，满足“最多成功一次”。
 */
export function consumeChallenge(db: DatabaseSync, id: string, now = Date.now()): ConsumeOutcome {
  const startedAt = now;
  for (let attempt = 0; ; attempt++) {
    try {
      db.exec("BEGIN IMMEDIATE");
      break;
    } catch (err) {
      // 单进程并发调用时其他协程可能持锁；短暂退避后重试。
      if (isBusyError(err) && attempt < 50) {
        const waitMs = 10 + attempt * 5;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, waitMs);
        continue;
      }
      throw err;
    }
  }
  try {
    const row = getChallenge(db, id);
    if (!row) {
      db.exec("ROLLBACK");
      return { outcome: "not-found" };
    }
    if (row.status === "consumed") {
      db.exec("ROLLBACK");
      return { outcome: "already-consumed", row };
    }
    if (row.expires_at <= now) {
      db.prepare("UPDATE challenges SET status = 'expired' WHERE id = ?").run(id);
      db.exec("COMMIT");
      return { outcome: "expired", row: getChallenge(db, id)! };
    }
    db.prepare("UPDATE challenges SET status = 'consumed', consumed_at = ? WHERE id = ? AND status = 'pending'").run(now, id);
    db.exec("COMMIT");
    return { outcome: "consumed", row: getChallenge(db, id)! };
  } catch (err) {
    db.exec("ROLLBACK");
    if (isBusyError(err)) {
      return consumeChallenge(db, id, Date.now() > startedAt ? Date.now() : startedAt);
    }
    throw err;
  }
}

function isBusyError(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return code === "SQLITE_BUSY" || code === "SQLITE_LOCKED";
}

export function markExpiredChallenges(db: DatabaseSync, now = Date.now()): number {
  const res = db
    .prepare("UPDATE challenges SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?")
    .run(now);
  return Number(res.changes ?? 0);
}

export function insertTranscript(
  db: DatabaseSync,
  data: Omit<TranscriptRow, "id" | "created_at">,
): TranscriptRow {
  const id = newId("trn");
  const now = Date.now();
  db.prepare(
    `INSERT INTO transcripts (id, kind, group_id, context, y, commitment, challenge, response, transcript_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, data.kind, data.group_id, data.context, data.y, data.commitment, data.challenge, data.response, data.transcript_json, now);
  return db.prepare("SELECT * FROM transcripts WHERE id = ?").get(id) as unknown as TranscriptRow;
}

export function getTranscript(db: DatabaseSync, id: string): TranscriptRow | null {
  const row = db.prepare("SELECT * FROM transcripts WHERE id = ?").get(id) as unknown as TranscriptRow | undefined;
  return row ?? null;
}

export function listTranscripts(db: DatabaseSync, limit = 100): TranscriptRow[] {
  return db.prepare("SELECT * FROM transcripts ORDER BY created_at DESC LIMIT ?").all(limit) as unknown as TranscriptRow[];
}

export function insertVerification(
  db: DatabaseSync,
  data: Omit<VerificationRow, "id" | "created_at">,
): VerificationRow {
  const id = newId("ver");
  const now = Date.now();
  db.prepare(
    `INSERT INTO verifications (id, transcript_id, challenge_id, kind, group_id, context, valid, reason, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, data.transcript_id, data.challenge_id, data.kind, data.group_id, data.context, data.valid, data.reason, now);
  return db.prepare("SELECT * FROM verifications WHERE id = ?").get(id) as unknown as VerificationRow;
}

export function listVerifications(db: DatabaseSync, limit = 100): VerificationRow[] {
  return db.prepare("SELECT * FROM verifications ORDER BY created_at DESC LIMIT ?").all(limit) as unknown as VerificationRow[];
}

/**
 * 公开导出：仅包含可公开的字段。即使代码里存在秘密值，
 * 这里也使用白名单挑选字段，保证 x/nonce 不被导出。
 */
export function exportPublicData(db: DatabaseSync) {
  const groups = listGroups(db);
  const challenges = db
    .prepare("SELECT id, group_id, context, y, commitment, challenge, status, created_at, expires_at, consumed_at FROM challenges")
    .all();
  const transcripts = listTranscripts(db, 10000).map((t) => ({
    id: t.id,
    kind: t.kind,
    groupId: t.group_id,
    context: t.context,
    y: t.y,
    commitment: t.commitment,
    challenge: t.challenge,
    response: t.response,
    createdAt: t.created_at,
  }));
  const verifications = listVerifications(db, 10000);
  const digest = createHash("sha256")
    .update(JSON.stringify({ groups, challenges, transcripts }))
    .digest("hex");
  return {
    exportedAt: new Date().toISOString(),
    warning: "仅含公开数据；教学实现，禁止用于生产身份认证。",
    groups,
    challenges,
    transcripts,
    verifications,
    digest,
  };
}


