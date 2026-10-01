import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { openDatabase, exportPublicData } from "../src/server/db.js";
import {
  issueChallenge,
  submitInteractiveResponse,
  verifyImportedTranscript,
  parseTranscriptJson,
  ValidationError,
} from "../src/server/service.js";
import { GROUP_SMALL } from "../src/crypto/groups.js";
import {
  generateSecretKey,
  publicKeyFromSecret,
  commit,
  buildInteractiveTranscript,
  proveFiatShamir,
} from "../src/crypto/schnorr.js";

let dbPath: string;
let db: DatabaseSync;

before(() => {
  dbPath = join(mkdtempSync(join(tmpdir(), "schnorr-test-")), "t.sqlite");
  db = openDatabase(dbPath);
});

after(() => db.close());

test("非法公钥/承诺在签发时拒绝", () => {
  assert.throws(
    () =>
      issueChallenge(db, {
        groupId: GROUP_SMALL.id,
        context: "ctx",
        y: 1n, // 单位元
        commitment: 9n,
      }),
    ValidationError,
  );
  assert.throws(
    () =>
      issueChallenge(db, {
        groupId: GROUP_SMALL.id,
        context: "ctx",
        y: 8n,
        commitment: 23n, // 越界
      }),
    ValidationError,
  );
  assert.throws(() => issueChallenge(db, {
    groupId: GROUP_SMALL.id,
    context: "",
    y: 8n,
    commitment: 9n,
  }), ValidationError);
});

test("挑战一次消费：成功后重复提交失败", () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const pk = publicKeyFromSecret(GROUP_SMALL, sk);
  const cobj = commit(GROUP_SMALL);
  const ch = issueChallenge(db, {
    groupId: GROUP_SMALL.id,
    context: "ctx-once",
    y: pk.y,
    commitment: cobj.commitment,
  });
  const t = buildInteractiveTranscript(GROUP_SMALL, sk, "ctx-once", cobj, ch.challenge);
  const r1 = submitInteractiveResponse(db, { challengeId: ch.challengeId, response: t.response });
  assert.equal(r1.valid, true);
  const r2 = submitInteractiveResponse(db, { challengeId: ch.challengeId, response: t.response });
  assert.equal(r2.valid, false);
  assert.match(r2.reason ?? "", /已被消费/);
});

test("并发提交同一挑战最多成功一次", async () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const pk = publicKeyFromSecret(GROUP_SMALL, sk);
  const cobj = commit(GROUP_SMALL);
  const ch = issueChallenge(db, {
    groupId: GROUP_SMALL.id,
    context: "ctx-race",
    y: pk.y,
    commitment: cobj.commitment,
  });
  const t = buildInteractiveTranscript(GROUP_SMALL, sk, "ctx-race", cobj, ch.challenge);
  const results = await Promise.all(
    Array.from({ length: 8 }, () =>
      Promise.resolve(
        submitInteractiveResponse(db, { challengeId: ch.challengeId, response: t.response }),
      ),
    ),
  );
  assert.equal(results.filter((r) => r.valid).length, 1);
});

test("过期挑战提交失败", async () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const pk = publicKeyFromSecret(GROUP_SMALL, sk);
  const cobj = commit(GROUP_SMALL);
  const ch = issueChallenge(db, {
    groupId: GROUP_SMALL.id,
    context: "ctx-ttl",
    y: pk.y,
    commitment: cobj.commitment,
    ttlMs: 50,
  });
  await new Promise((r) => setTimeout(r, 80));
  const t = buildInteractiveTranscript(GROUP_SMALL, sk, "ctx-ttl", cobj, ch.challenge);
  const r = submitInteractiveResponse(db, { challengeId: ch.challengeId, response: t.response });
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /过期/);
});

test("篡改响应被验证拒绝，但挑战同样只消费一次", () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const pk = publicKeyFromSecret(GROUP_SMALL, sk);
  const cobj = commit(GROUP_SMALL);
  const ch = issueChallenge(db, {
    groupId: GROUP_SMALL.id,
    context: "ctx-tamper",
    y: pk.y,
    commitment: cobj.commitment,
  });
  const t = buildInteractiveTranscript(GROUP_SMALL, sk, "ctx-tamper", cobj, ch.challenge);
  const r1 = submitInteractiveResponse(db, {
    challengeId: ch.challengeId,
    response: (t.response + 1n) % GROUP_SMALL.q,
  });
  assert.equal(r1.valid, false);
  const r2 = submitInteractiveResponse(db, { challengeId: ch.challengeId, response: t.response });
  assert.equal(r2.valid, false, "即使首次验证失败，挑战也不能再被使用");
});

test("FS 转录导入验证与上下文绑定", () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const proof = proveFiatShamir(GROUP_SMALL, sk, "import-ctx");
  const json = JSON.parse(JSON.stringify({
    kind: proof.kind,
    protocolVersion: proof.protocolVersion,
    groupId: proof.groupId,
    context: proof.context,
    y: proof.y.toString(),
    commitment: proof.commitment.toString(),
    challenge: proof.challenge.toString(),
    response: proof.response.toString(),
  }));
  assert.equal(verifyImportedTranscript(db, { transcript: json }).valid, true);
  assert.equal(
    verifyImportedTranscript(db, { transcript: { ...json, context: "x" }, expectedContext: "import-ctx" }).valid,
    false,
  );
});

test("交互转录不能通过 /verify 无挑战背书导入（防止类型混用）", () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const proof = proveFiatShamir(GROUP_SMALL, sk, "mix-ctx");
  const disguised = {
    kind: "interactive",
    protocolVersion: proof.protocolVersion,
    groupId: proof.groupId,
    context: proof.context,
    y: proof.y.toString(),
    commitment: proof.commitment.toString(),
    challenge: proof.challenge.toString(),
    response: proof.response.toString(),
  };
  assert.throws(() => verifyImportedTranscript(db, { transcript: disguised }), ValidationError);
});

test("解析非法转录 JSON 抛出校验错误", () => {
  assert.throws(() => parseTranscriptJson(null), ValidationError);
  assert.throws(() => parseTranscriptJson({}), ValidationError);
  assert.throws(
    () =>
      parseTranscriptJson({
        kind: "interactive",
        protocolVersion: "schnorr-zkp-v1",
        groupId: "small-demo",
        context: "c",
        y: "abc",
        commitment: "1",
        challenge: "1",
        response: "1",
      }),
    ValidationError,
  );
});

test("服务重启后消费状态持久（重新打开数据库，旧挑战仍为 consumed）", () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const pk = publicKeyFromSecret(GROUP_SMALL, sk);
  const cobj = commit(GROUP_SMALL);
  const ch = issueChallenge(db, {
    groupId: GROUP_SMALL.id,
    context: "ctx-restart",
    y: pk.y,
    commitment: cobj.commitment,
  });
  const t = buildInteractiveTranscript(GROUP_SMALL, sk, "ctx-restart", cobj, ch.challenge);
  assert.equal(submitInteractiveResponse(db, { challengeId: ch.challengeId, response: t.response }).valid, true);

  db.close();
  const reopened = openDatabase(dbPath);
  const again = submitInteractiveResponse(reopened, { challengeId: ch.challengeId, response: t.response });
  assert.equal(again.valid, false);
  assert.match(again.reason ?? "", /已被消费/);
  reopened.close();
  db = openDatabase(dbPath);
});

test("公开导出不包含秘密字段", () => {
  const exported = JSON.stringify(exportPublicData(db));
  assert.doesNotMatch(exported, /secretX/);
  assert.doesNotMatch(exported, /"nonce"/);
  assert.doesNotMatch(exported, /"x":/);
});
