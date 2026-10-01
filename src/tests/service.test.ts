import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { rmSync } from "node:fs";
import { SchnorrService } from "../service.js";
import { SMALL_GROUP } from "../params.js";
import { commit, generateKeyPair, respond, dec } from "../proof.js";
import { modPow } from "../bignum.js";

function cleanup(dir: string, svc: SchnorrService): void {
  svc.close();
  // Windows 上 SQLite WAL/SHM 句柄释放可能有短暂延迟
  for (let i = 0; i < 10; i++) {
    try { rmSync(dir, { recursive: true, force: true }); return; }
    catch { }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}
function tempService(): { svc: SchnorrService; dir: string } {
  const dir = resolve(tmpdir(), `schnorr-svc-${Math.random().toString(36).slice(2)}-${Date.now()}`);
  return { svc: SchnorrService.open(resolve(dir, "schnorr.db")), dir };
}

test("交互三段流程成功，且转录入库", () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    const { secretScalar, publicKey } = generateKeyPair(gp);
    const { nonce, commitment } = commit(gp);
    const issued = svc.issueChallenge({
      group: gp.label, context: "ctx", publicKey: dec(publicKey), commitment: dec(commitment),
    });
    const s = respond(gp, nonce, BigInt(issued.challenge), secretScalar);
    const r = svc.submitResponse({ challengeId: issued.challengeId, response: dec(s) });
    assert.equal(r.valid, true);
    assert.ok(r.transcriptId);
    assert.equal(svc.listTranscripts().length, 1);
  } finally { cleanup(dir, svc); }
});

test("重复提交同一挑战被拒绝", () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = svc.issueChallenge({ group: gp.label, context: "x", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment) });
    const s = dec(respond(gp, cc.nonce, BigInt(issued.challenge), kp.secretScalar));
    assert.equal(svc.submitResponse({ challengeId: issued.challengeId, response: s }).valid, true);
    assert.throws(() => svc.submitResponse({ challengeId: issued.challengeId, response: s }), /消费/);
  } finally { cleanup(dir, svc); }
});

test("错误响应被标记无效，且挑战照样消费", () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = svc.issueChallenge({ group: gp.label, context: "x", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment) });
    const r = svc.submitResponse({ challengeId: issued.challengeId, response: "0" });
    assert.equal(r.valid, false);
    // 挑战已消费，无法再试
    assert.throws(() => svc.submitResponse({ challengeId: issued.challengeId, response: "1" }), /消费/);
    // 无效证明不产生转录，但有验证记录
    assert.equal(svc.listTranscripts().length, 0);
    assert.ok(svc.listVerifications().some((v) => v.valid === 0));
  } finally { cleanup(dir, svc); }
});

test("跨上下文复用被拒绝", () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = svc.issueChallenge({ group: gp.label, context: "A", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment) });
    const s = dec(respond(gp, cc.nonce, BigInt(issued.challenge), kp.secretScalar));
    assert.throws(
      () => svc.submitResponse({ challengeId: issued.challengeId, response: s, context: "B" }),
      /上下文/
    );
  } finally { cleanup(dir, svc); }
});

test("过期挑战提交被拒绝", async () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = svc.issueChallenge({
      group: gp.label, context: "x", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment), ttlMs: 1,
    });
    await new Promise((r) => setTimeout(r, 5));
    assert.throws(() => svc.submitResponse({ challengeId: issued.challengeId, response: "1" }), /过期/);
  } finally { cleanup(dir, svc); }
});

test("同一挑战并发提交最多成功一次", async () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = svc.issueChallenge({ group: gp.label, context: "x", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment) });
    const s = dec(respond(gp, cc.nonce, BigInt(issued.challenge), kp.secretScalar));
    const outcomes = await Promise.all(
      Array.from({ length: 8 }, async () => {
        try {
          return svc.submitResponse({ challengeId: issued.challengeId, response: s }).valid ? "ok" : "invalid";
        } catch {
          return "rejected";
        }
      })
    );
    assert.equal(outcomes.filter((o) => o === "ok").length, 1);
    assert.equal(outcomes.filter((o) => o === "rejected").length, 7);
  } finally { cleanup(dir, svc); }
});

test("服务重启后消费状态持久（已消费挑战仍被拒绝）", () => {
  const { dir } = tempService();
  const gp = SMALL_GROUP;
  let svc = SchnorrService.open(resolve(dir, "schnorr.db"));
  try {
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = svc.issueChallenge({ group: gp.label, context: "x", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment) });
    const s = dec(respond(gp, cc.nonce, BigInt(issued.challenge), kp.secretScalar));
    svc.submitResponse({ challengeId: issued.challengeId, response: s });

    // 重新打开数据库，模拟重启
    svc.close();
    svc = SchnorrService.open(resolve(dir, "schnorr.db"));
    assert.throws(() => svc.submitResponse({ challengeId: issued.challengeId, response: s }), /消费/);
  } finally {
    cleanup(dir, svc);
  }
});

test("非法公开密钥/承诺在签发时被拒绝", () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    assert.throws(
      () => svc.issueChallenge({ group: gp.label, context: "x", publicKey: "2", commitment: dec(modPow(gp.g, 3n, gp.p)) }),
      /公开密钥/
    );
    assert.throws(
      () => svc.issueChallenge({ group: gp.label, context: "x", publicKey: dec(modPow(gp.g, 3n, gp.p)), commitment: "999999" }),
      /承诺/
    );
  } finally { cleanup(dir, svc); }
});

test("导出内容不含秘密字段", () => {
  const { svc, dir } = tempService();
  try {
    const gp = SMALL_GROUP;
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = svc.issueChallenge({ group: gp.label, context: "x", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment) });
    const s = dec(respond(gp, cc.nonce, BigInt(issued.challenge), kp.secretScalar));
    svc.submitResponse({ challengeId: issued.challengeId, response: s });
    const text = JSON.stringify(svc.exportPublic());
    assert.ok(!text.includes("secretScalar"));
    assert.ok(!text.includes("nonce"));
  } finally { cleanup(dir, svc); }
});

test("nonce 重用样本恢复固定私钥；不同 nonce 不误报", () => {
  const { svc, dir } = tempService();
  try {
    const r = svc.analyzeNonceReuseSamples("small-unsafe-demo");
    assert.equal(r.sameNonce.recoveredSecret, "7");
    assert.equal(r.differentNonce.recovered, false);
  } finally { cleanup(dir, svc); }
});





