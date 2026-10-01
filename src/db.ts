// SQLite 存储层。
// 仅持久化公开参数、待验证挑战、公开证明转录与验证记录。
// 严禁默认保存私有标量 x 与 nonce k（表结构中没有对应列）。
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { uuid } from "./bignum.js";

export interface StoredChallenge {
  id: string;
  group_label: string;
  context: string;
  public_key: string;
  commitment: string;
  challenge: string;
  status: "pending" | "consumed" | "expired";
  expires_at: string; // ISO
  created_at: string;
  consumed_at: string | null;
  response: string | null;
  verify_valid: number | null;
  verify_reason: string | null;
}

export interface StoredTranscript {
  id: string;
  kind: "interactive" | "fiat-shamir";
  group_label: string;
  context: string;
  public_key: string;
  commitment: string;
  challenge: string;
  response: string;
  source: string; // api | cli | import
  created_at: string;
}

export interface StoredVerification {
  id: string;
  transcript_id: string | null;
  kind: string;
  group_label: string;
  context: string;
  valid: number;
  reason: string | null;
  detail: string | null; // JSON 检查轨迹
  created_at: string;
}

export function openDb(file: string): DatabaseSync {
  mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode=WAL;");
  db.exec("PRAGMA foreign_keys=ON;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS groups_meta (
      label TEXT PRIMARY KEY,
      version TEXT NOT NULL,
      p TEXT NOT NULL,
      q TEXT NOT NULL,
      g TEXT NOT NULL,
      unsafe_small INTEGER NOT NULL,
      check_result TEXT NOT NULL,
      registered_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      group_label TEXT NOT NULL,
      context TEXT NOT NULL,
      public_key TEXT NOT NULL,
      commitment TEXT NOT NULL,
      challenge TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      consumed_at TEXT,
      response TEXT,
      verify_valid INTEGER,
      verify_reason TEXT
    );
    CREATE TABLE IF NOT EXISTS transcripts (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      group_label TEXT NOT NULL,
      context TEXT NOT NULL,
      public_key TEXT NOT NULL,
      commitment TEXT NOT NULL,
      challenge TEXT NOT NULL,
      response TEXT NOT NULL,
      source TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS verifications (
      id TEXT PRIMARY KEY,
      transcript_id TEXT,
      kind TEXT NOT NULL,
      group_label TEXT NOT NULL,
      context TEXT NOT NULL,
      valid INTEGER NOT NULL,
      reason TEXT,
      detail TEXT,
      created_at TEXT NOT NULL
    );
  `);
  return db;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export interface AppDB {
  db: DatabaseSync;
  upsertGroup(meta: {
    label: string; version: string; p: string; q: string; g: string;
    unsafeSmall: boolean; checkResult: string;
  }): void;
  listGroups(): Array<Record<string, unknown>>;

  createChallenge(args: {
    groupLabel: string; context: string; publicKey: string; commitment: string;
    challenge: string; expiresAt: string;
  }): StoredChallenge;
  getChallenge(id: string): StoredChallenge | null;
  listChallenges(): StoredChallenge[];
  /** 原子消费：仅当 pending 且未过期时成功（BEGIN IMMEDIATE 串行化并发）。 */
  consumeChallenge(id: string, response: string, verifyValid: boolean, reason: string | null): StoredChallenge | "missing" | "expired" | "used";
  markExpiredPending(now: Date): number;

  insertTranscript(t: NewTranscript): StoredTranscript;
  listTranscripts(): StoredTranscript[];
  getTranscript(id: string): StoredTranscript | null;

  insertVerification(v: Omit<StoredVerification, "id" | "created_at">): StoredVerification;
  listVerifications(): StoredVerification[];
}

export interface NewTranscript {
  id?: string;
  kind: "interactive" | "fiat-shamir";
  groupLabel: string;
  context: string;
  publicKey: string;
  commitment: string;
  challenge: string;
  response: string;
  source: string;
}

export function wrap(db: DatabaseSync): AppDB {
  const app: AppDB = {
    db,

    upsertGroup(meta) {
      db.prepare(`INSERT INTO groups_meta(label,version,p,q,g,unsafe_small,check_result,registered_at)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(label) DO UPDATE SET
          version=excluded.version,p=excluded.p,q=excluded.q,g=excluded.g,
          unsafe_small=excluded.unsafe_small,check_result=excluded.check_result`)
        .run(meta.label, meta.version, meta.p, meta.q, meta.g, meta.unsafeSmall ? 1 : 0,
             meta.checkResult, nowIso());
    },

    listGroups() {
      return db.prepare("SELECT * FROM groups_meta ORDER BY label").all() as Array<Record<string, unknown>>;
    },

    createChallenge(args) {
      const row: StoredChallenge = {
        id: uuid(),
        group_label: args.groupLabel,
        context: args.context,
        public_key: args.publicKey,
        commitment: args.commitment,
        challenge: args.challenge,
        status: "pending",
        expires_at: args.expiresAt,
        created_at: nowIso(),
        consumed_at: null,
        response: null,
        verify_valid: null,
        verify_reason: null,
      };
      db.prepare(`INSERT INTO challenges
        (id,group_label,context,public_key,commitment,challenge,status,expires_at,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(row.id, row.group_label, row.context, row.public_key, row.commitment,
             row.challenge, row.status, row.expires_at, row.created_at);
      return row;
    },

    getChallenge(id) {
      return (db.prepare("SELECT * FROM challenges WHERE id=?").get(id) as unknown as StoredChallenge | undefined) ?? null;
    },

    listChallenges() {
      return db.prepare("SELECT * FROM challenges ORDER BY created_at DESC").all() as unknown as StoredChallenge[];
    },

    consumeChallenge(id, response, verifyValid, reason) {
      // 立即事务，保证同一挑战的并发提交最多一个成功
      db.exec("BEGIN IMMEDIATE");
      try {
        const row = (db.prepare("SELECT * FROM challenges WHERE id=?").get(id) as unknown as StoredChallenge | undefined) ?? null;
        if (!row) { db.exec("ROLLBACK"); return "missing"; }
        if (row.status === "consumed") { db.exec("ROLLBACK"); return "used"; }
        if (Date.now() > Date.parse(row.expires_at)) {
          db.prepare("UPDATE challenges SET status='expired' WHERE id=?").run(id);
          db.exec("COMMIT");
          return "expired";
        }
        db.prepare(`UPDATE challenges SET status='consumed', consumed_at=?, response=?,
          verify_valid=?, verify_reason=? WHERE id=?`)
          .run(nowIso(), response, verifyValid ? 1 : 0, reason, id);
        db.exec("COMMIT");
        return app.getChallenge(id) ?? row;
      } catch (e) {
        db.exec("ROLLBACK");
        throw e;
      }
    },

    markExpiredPending(now) {
      const info = db.prepare("UPDATE challenges SET status='expired' WHERE status='pending' AND expires_at <= ?")
        .run(now.toISOString());
      return Number(info.changes ?? 0);
    },

    insertTranscript(t) {
      const row: StoredTranscript = {
        id: t.id ?? uuid(),
        kind: t.kind,
        group_label: t.groupLabel,
        context: t.context,
        public_key: t.publicKey,
        commitment: t.commitment,
        challenge: t.challenge,
        response: t.response,
        source: t.source,
        created_at: nowIso(),
      };
      db.prepare(`INSERT INTO transcripts
        (id,kind,group_label,context,public_key,commitment,challenge,response,source,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(row.id, row.kind, row.group_label, row.context, row.public_key, row.commitment,
             row.challenge, row.response, row.source, row.created_at);
      return row;
    },

    listTranscripts() {
      return db.prepare("SELECT * FROM transcripts ORDER BY created_at DESC").all() as unknown as StoredTranscript[];
    },

    getTranscript(id) {
      return (db.prepare("SELECT * FROM transcripts WHERE id=?").get(id) as StoredTranscript | undefined) ?? null;
    },

    insertVerification(v) {
      const row: StoredVerification = {
        id: uuid(),
        transcript_id: v.transcript_id,
        kind: v.kind,
        group_label: v.group_label,
        context: v.context,
        valid: v.valid ? 1 : 0,
        reason: v.reason,
        detail: v.detail,
        created_at: nowIso(),
      };
      db.prepare(`INSERT INTO verifications
        (id,transcript_id,kind,group_label,context,valid,reason,detail,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(row.id, row.transcript_id, row.kind, row.group_label, row.context,
             row.valid, row.reason, row.detail, row.created_at);
      return row;
    },

    listVerifications() {
      return db.prepare("SELECT * FROM verifications ORDER BY created_at DESC").all() as unknown as StoredVerification[];
    },
  };
  return app;
}

export function initDefaultStore(file: string): AppDB {
  const db = openDb(file);
  const app = wrap(db);
  const { GROUPS, checkGroupParams } = require("./params.js") as typeof import("./params.js");
  for (const gp of Object.values(GROUPS)) {
    const check = checkGroupParams(gp);
    app.upsertGroup({
      label: gp.label,
      version: gp.version,
      p: gp.p.toString(10),
      q: gp.q.toString(10),
      g: gp.g.toString(10),
      unsafeSmall: gp.unsafeSmall,
      checkResult: JSON.stringify(check),
    });
  }
  return app;
}

