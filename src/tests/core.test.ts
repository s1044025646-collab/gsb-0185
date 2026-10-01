import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { rmSync } from "node:fs";
import { SMALL_GROUP, LARGE_GROUP, checkGroupParams, checkGroupElement } from "../params.js";
import {
  bi, dec, commit, fiatShamirChallenge, generateKeyPair, respond,
  verifyTranscript, buildTranscript, analyzeNonceReuse,
} from "../proof.js";
import { modPow, deterministicRandom, randomScalar } from "../bignum.js";
import { canonical, tlv } from "../encoding.js";

test("两组固定参数均通过参数检查", () => {
  for (const gp of [SMALL_GROUP, LARGE_GROUP]) {
    const r = checkGroupParams(gp);
    assert.equal(r.ok, true, r.errors.join("; "));
    assert.equal(modPow(gp.g, gp.q, gp.p), 1n);
  }
  assert.equal(SMALL_GROUP.unsafeSmall, true);
});

test("非法生成元被参数检查拒绝", () => {
  const bad = { ...SMALL_GROUP, g: 2n }; // 2 在该群中阶不是 101
  assert.equal(checkGroupParams(bad).ok, false);
  const identity = { ...SMALL_GROUP, g: 1n };
  assert.equal(checkGroupParams(identity).ok, false);
});

test("非法群元素被拒绝（范围 + 子群）", () => {
  assert.ok(checkGroupElement(0n, SMALL_GROUP));
  assert.ok(checkGroupElement(1n, SMALL_GROUP));
  assert.ok(checkGroupElement(SMALL_GROUP.p, SMALL_GROUP));
  assert.ok(checkGroupElement(SMALL_GROUP.p + 5n, SMALL_GROUP));
  // 2 不是阶 q 子群元素（其阶为 606 的其他因子）
  assert.ok(checkGroupElement(2n, SMALL_GROUP));
  // 合法公钥通过
  const { publicKey } = generateKeyPair(SMALL_GROUP);
  assert.equal(checkGroupElement(publicKey, SMALL_GROUP), null);
});

test("Fiat-Shamir 正确证明满足验证方程", () => {
  const gp = SMALL_GROUP;
  const x = 7n;
  const y = modPow(gp.g, x, gp.p);
  const { nonce, commitment } = commit(gp);
  const c = fiatShamirChallenge(gp, y, commitment, "ctx");
  const s = respond(gp, nonce, c, x);
  const tr = buildTranscript({ type: "fiat-shamir", gp, context: "ctx", publicKey: y, commitment, challenge: c, response: s });
  const r = verifyTranscript(tr, gp, "fiat-shamir");
  assert.equal(r.valid, true, r.reason);
  // 真实验证方程：g^s * y^c mod p == t
  assert.equal((modPow(gp.g, s, gp.p) * modPow(y, c, gp.p)) % gp.p, commitment);
});

test("篡改响应导致方程失败", () => {
  const gp = SMALL_GROUP;
  const x = 3n;
  const y = modPow(gp.g, x, gp.p);
  const { nonce, commitment } = commit(gp);
  const c = fiatShamirChallenge(gp, y, commitment, "ctx");
  const s = respond(gp, nonce, c, x);
  const tr = buildTranscript({ type: "fiat-shamir", gp, context: "ctx", publicKey: y, commitment, challenge: c, response: (s + 1n) % gp.q });
  assert.equal(verifyTranscript(tr, gp, "fiat-shamir").valid, false);
});

test("替换上下文导致 Fiat-Shamir 挑战不匹配", () => {
  const gp = SMALL_GROUP;
  const x = 9n;
  const y = modPow(gp.g, x, gp.p);
  const { nonce, commitment } = commit(gp);
  const c = fiatShamirChallenge(gp, y, commitment, "context-A");
  const s = respond(gp, nonce, c, x);
  const tr = buildTranscript({ type: "fiat-shamir", gp, context: "context-B", publicKey: y, commitment, challenge: c, response: s });
  const r = verifyTranscript(tr, gp, "fiat-shamir");
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /Fiat-Shamir/);
});

test("挑战与响应边界值 0 与 q-1 被正确接受/拒绝", () => {
  const gp = SMALL_GROUP;
  // 构造交互转录，挑战 c=0 时 s=k，应验证通过
  const x = 4n, k = 10n;
  const y = modPow(gp.g, x, gp.p);
  const t = modPow(gp.g, k, gp.p);
  const s = respond(gp, k, 0n, x);
  assert.equal(s, k);
  const tr = buildTranscript({ type: "interactive", gp, context: "z", publicKey: y, commitment: t, challenge: 0n, response: s });
  assert.equal(verifyTranscript(tr, gp, "interactive").valid, true);
  // 挑战 = q 越界
  const bad = { ...tr, challenge: dec(gp.q) };
  assert.equal(verifyTranscript(bad, gp, "interactive").valid, false);
  // 响应 = q 越界
  const bad2 = { ...tr, response: dec(gp.q) };
  assert.equal(verifyTranscript(bad2, gp, "interactive").valid, false);
  // 负数
  const bad3 = { ...tr, response: "-1" };
  assert.equal(verifyTranscript(bad3, gp, "interactive").valid, false);
});

test("交互与非交互转录类型禁止混用", () => {
  const gp = SMALL_GROUP;
  const x = 5n;
  const y = modPow(gp.g, x, gp.p);
  const { nonce, commitment } = commit(gp);
  const c = fiatShamirChallenge(gp, y, commitment, "ctx");
  const s = respond(gp, nonce, c, x);
  const ni = buildTranscript({ type: "fiat-shamir", gp, context: "ctx", publicKey: y, commitment, challenge: c, response: s });
  // 以 interactive 期望类型验证非交互转录 -> 拒绝
  assert.equal(verifyTranscript(ni, gp, "interactive").valid, false);
  // 非交互转录冒充交互转录提交：Fiat-Shamir 分支不被触发，
  // 但交互流程中真实挑战由服务端签发；此处篡改 type 且不携带交互挑战来源，
  // 服务层提交时按 interactive 验证——验证者若错误地按 fiat-shamir 验证一个被改类型的转录也应失败：
  const tampered = { ...ni, transcriptType: "interactive" as const };
  // 把它当非交互验证会在类型守卫处被拒绝（禁止混用）
  assert.equal(verifyTranscript(tampered, gp, "fiat-shamir").valid, false);
  // 未知类型一律拒绝
  const weird = { ...ni, transcriptType: "mystery" as unknown as "fiat-shamir" };
  assert.equal(verifyTranscript(weird, gp, "interactive").valid, false);
});

test("TLV 长度边界消除编码歧义", () => {
  const a = canonical([1, "ab"], [1, "c"]);
  const b = canonical([1, "a"], [1, "bc"]);
  assert.ok(!a.equals(b));
  // 标签不同也不同
  const c1 = tlv(1, "x");
  const c2 = tlv(2, "x");
  assert.ok(!c1.equals(c2));
  // 整数与字符串语义分离（同数字也不会与字符串混淆）
  const n1 = tlv(3, 1n);
  const s1 = tlv(3, "1");
  assert.ok(!n1.equals(s1));
});

test("确定性随机源可注入且范围合法；默认不使用固定种子", async () => {
  const rand = deterministicRandom(Buffer.from([0xff, 0x03]));
  for (let i = 0; i < 50; i++) {
    const v = randomScalar(SMALL_GROUP.q, rand);
    assert.ok(v >= 1n && v < SMALL_GROUP.q);
  }
  // 系统随机：两次 keygen 不同（极高概率）
  const a = generateKeyPair(SMALL_GROUP);
  const b = generateKeyPair(SMALL_GROUP);
  assert.notEqual(a.secretScalar, b.secretScalar);
});

test("nonce 重用恢复秘密：相同 nonce 不同挑战", () => {
  const gp = SMALL_GROUP;
  const x = 11n, k = 17n;
  const t = modPow(gp.g, k, gp.p);
  const r = analyzeNonceReuse(
    gp,
    { commitment: dec(t), challenge: dec(3n), response: dec(respond(gp, k, 3n, x)) },
    { commitment: dec(t), challenge: dec(8n), response: dec(respond(gp, k, 8n, x)) }
  );
  assert.equal(r.recovered, true);
  assert.equal(r.secretScalar, "11");
});

test("不同 nonce 的合法两份转录不会误报", () => {
  const gp = SMALL_GROUP;
  const x = 11n, k1 = 17n, k2 = 19n;
  const r = analyzeNonceReuse(
    gp,
    { commitment: dec(modPow(gp.g, k1, gp.p)), challenge: dec(3n), response: dec(respond(gp, k1, 3n, x)) },
    { commitment: dec(modPow(gp.g, k2, gp.p)), challenge: dec(8n), response: dec(respond(gp, k2, 8n, x)) }
  );
  assert.equal(r.recovered, false);
});

test("相同挑战不构成恢复条件", () => {
  const gp = SMALL_GROUP;
  const x = 11n, k = 17n;
  const t = modPow(gp.g, k, gp.p);
  const r = analyzeNonceReuse(
    gp,
    { commitment: dec(t), challenge: dec(3n), response: dec(respond(gp, k, 3n, x)) },
    { commitment: dec(t), challenge: dec(3n), response: dec(respond(gp, k, 3n, x)) }
  );
  assert.equal(r.recovered, false);
});

test("大参数集完整证明流程通过", () => {
  const gp = LARGE_GROUP;
  const { secretScalar, publicKey } = generateKeyPair(gp);
  const { nonce, commitment } = commit(gp);
  const c = fiatShamirChallenge(gp, publicKey, commitment, "large");
  const s = respond(gp, nonce, c, secretScalar);
  const tr = buildTranscript({ type: "fiat-shamir", gp, context: "large", publicKey, commitment, challenge: c, response: s });
  assert.equal(verifyTranscript(tr, gp, "fiat-shamir").valid, true);
});

