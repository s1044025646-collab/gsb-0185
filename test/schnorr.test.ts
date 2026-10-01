import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GROUP_SMALL,
  GROUP_256,
  checkGroup,
  checkGroupElement,
} from "../src/crypto/groups.js";
import {
  generateSecretKey,
  parseSecretKey,
  publicKeyFromSecret,
  commitWithNonce,
  respond,
  fiatShamirChallenge,
  proveFiatShamir,
  verifyInteractive,
  verifyFiatShamir,
  INTERACTIVE_KIND,
  FS_KIND,
  PROTOCOL_VERSION,
} from "../src/crypto/schnorr.js";
import { analyzeNonceReuse } from "../src/crypto/analysis.js";
import { encodeFields, int, text } from "../src/crypto/encoding.js";
import {
  nonceReuseSamples,
  distinctNonceSamples,
  validHandSample,
  tamperedResponseSample,
  swappedContextSample,
} from "../src/samples.js";

test("两组群参数均通过子群阶/生成元检查", () => {
  assert.equal(checkGroup(GROUP_SMALL).ok, true);
  assert.equal(checkGroup(GROUP_256).ok, true);
});

test("可手算样本：真实方程验证通过，篡改响应失败", () => {
  const good = validHandSample();
  assert.equal(verifyInteractive(GROUP_SMALL, good.transcript).valid, true);
  const bad = tamperedResponseSample();
  const r = verifyInteractive(GROUP_SMALL, bad.transcript);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /g\^s/);
});

test("替换上下文：绑定原上下文时拒绝", () => {
  const sample = swappedContextSample();
  // 按转录自带上下文验证（数学成立）
  assert.equal(verifyInteractive(GROUP_SMALL, sample.transcript).valid, true);
  // 服务端按签发时上下文验证 => 拒绝跨上下文复用
  const r = verifyInteractive(GROUP_SMALL, sample.transcript, "lab-context-alpha");
  assert.equal(r.valid, false);
});

test("交互式证明：小参数与固定大参数上的完整流程", () => {
  for (const group of [GROUP_SMALL, GROUP_256]) {
    const sk = generateSecretKey(group);
    const pk = publicKeyFromSecret(group, sk);
    const c = commitWithNonce(group, group.q - 1n);
    const challenge = group.q - 2n;
    const s = respond(group, sk, c.nonce, challenge);
    const result = verifyInteractive(group, {
      kind: INTERACTIVE_KIND,
      protocolVersion: PROTOCOL_VERSION,
      groupId: group.id,
      context: "ctx",
      y: pk.y,
      commitment: c.commitment,
      challenge,
      response: s,
    });
    assert.equal(result.valid, true, result.reason);
  }
});

test("边界值：x=0 / x=q / c=0 / s=q 全部拒绝", () => {
  assert.throws(() => parseSecretKey(GROUP_SMALL, 0n));
  assert.throws(() => parseSecretKey(GROUP_SMALL, GROUP_SMALL.q));
  const sk = parseSecretKey(GROUP_SMALL, 3n);
  assert.throws(() => respond(GROUP_SMALL, sk, 1n, 0n));
  assert.throws(() => commitWithNonce(GROUP_SMALL, GROUP_SMALL.q));
  const pk = publicKeyFromSecret(GROUP_SMALL, sk);
  assert.equal(
    verifyInteractive(GROUP_SMALL, {
      kind: INTERACTIVE_KIND,
      protocolVersion: PROTOCOL_VERSION,
      groupId: GROUP_SMALL.id,
      context: "ctx",
      y: pk.y,
      commitment: 2n,
      challenge: 1n,
      response: GROUP_SMALL.q,
    }).valid,
    false,
  );
});

test("非法群元素：越界值、不在子群内的值、单位元均拒绝", () => {
  assert.equal(checkGroupElement(GROUP_SMALL, 0n).ok, false);
  assert.equal(checkGroupElement(GROUP_SMALL, GROUP_SMALL.p).ok, false);
  // g=5 不是模 23 的二次剩余，故 5^11 mod 23 = -1，不属于 q 阶子群
  assert.equal(checkGroupElement(GROUP_SMALL, 5n).ok, false);
  assert.equal(checkGroupElement(GROUP_SMALL, 1n, "non-identity").ok, false);
  assert.equal(checkGroupElement(GROUP_SMALL, 1n, "subgroup").ok, true);
});

test("Fiat-Shamir：证明可验证；改承诺/公钥/上下文均使重算挑战不一致", () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const proof = proveFiatShamir(GROUP_SMALL, sk, "ctx-A");
  assert.equal(verifyFiatShamir(GROUP_SMALL, proof).valid, true);

  assert.equal(verifyFiatShamir(GROUP_SMALL, { ...proof, commitment: 2n }).valid, false);
  assert.equal(verifyFiatShamir(GROUP_SMALL, { ...proof, y: proof.y + 1n }).valid, false);
  assert.equal(verifyFiatShamir(GROUP_SMALL, { ...proof, context: "ctx-B" }, "ctx-A").valid, false);

  // 确定性：相同输入挑战一致
  const c1 = fiatShamirChallenge(GROUP_SMALL, "ctx", proof.y, proof.commitment);
  const c2 = fiatShamirChallenge(GROUP_SMALL, "ctx", proof.y, proof.commitment);
  assert.equal(c1, c2);
  assert.notEqual(c1, 0n);
});

test("交互/非交互转录禁止混用", () => {
  const sk = generateSecretKey(GROUP_SMALL);
  const proof = proveFiatShamir(GROUP_SMALL, sk, "ctx");
  // FS 转录送入交互验证器 -> 类型不匹配
  assert.equal(verifyInteractive(GROUP_SMALL, proof as never).valid, false);
  // 交互转录送入 FS 验证器 -> 类型不匹配且无法重算挑战
  const interactive = { ...proof, kind: INTERACTIVE_KIND };
  assert.equal(verifyFiatShamir(GROUP_SMALL, interactive as never).valid, false);
  const asFs = {
    ...proof,
    protocolVersion: "schnorr-zkp-v0",
  };
  assert.equal(verifyFiatShamir(GROUP_SMALL, { ...asFs, kind: FS_KIND }).valid, false);
});

test("nonce 重用恢复私钥；不同 nonce 不误报", () => {
  const reuse = nonceReuseSamples();
  const r = analyzeNonceReuse(GROUP_SMALL, reuse.first, reuse.second);
  assert.equal(r.reuseDetected, true);
  assert.equal(r.recoveredX, reuse.recovered);
  assert.equal(r.publicKeyMatches, true);

  const safe = distinctNonceSamples();
  const sr = analyzeNonceReuse(GROUP_SMALL, safe.first, safe.second);
  assert.equal(sr.reuseDetected, false);
  assert.equal(sr.reason, "承诺不同（nonce 不同）");
});

test("规范编码无歧义：不同字段切分编码结果不同", () => {
  const a = encodeFields("D", [text("ab"), text("c")]);
  const b = encodeFields("D", [text("a"), text("bc")]);
  assert.notEqual(a.toString("hex"), b.toString("hex"));
  // 域分离
  const c = encodeFields("D", [text("ab"), text("c")]);
  const d = encodeFields("E", [text("ab"), text("c")]);
  assert.notEqual(c.toString("hex"), d.toString("hex"));
  // 整数与文本类型标签不同
  assert.notEqual(
    encodeFields("D", [text("1")]).toString("hex"),
    encodeFields("D", [int(1n)]).toString("hex"),
  );
});

test("显式输入与系统随机生成的私钥均在合法范围", () => {
  for (let i = 0; i < 20; i++) {
    const sk = generateSecretKey(GROUP_256);
    assert.ok(sk.x >= 1n && sk.x < GROUP_256.q);
  }
});
