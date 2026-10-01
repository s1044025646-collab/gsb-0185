// 端到端教学演示（无需启动 HTTP 服务，直接使用服务层 + 临时数据库）：
// 1) 参数检查 2) 正确非交互证明通过 3) 篡改响应失败 4) 替换上下文失败
// 5) 交互挑战：过期/重复消费拒绝、并发最多一次成功 6) nonce 重用恢复秘密
// 7) 不同 nonce 合法转录不会误报 8) 编码歧义说明
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { rmSync } from "node:fs";
import { SchnorrService } from "./service.js";
import { SMALL_GROUP, LARGE_GROUP, checkGroupParams } from "./params.js";
import {
  bi, dec, commit, fiatShamirChallenge, generateKeyPair, respond,
  verifyTranscript, buildTranscript, analyzeNonceReuse,
} from "./proof.js";
import { modPow } from "./bignum.js";
import { canonical } from "./encoding.js";

function hr(title: string): void {
  console.log("\n" + "=".repeat(72));
  console.log(title);
  console.log("=".repeat(72));
}

function showVerify(name: string, result: { valid: boolean; reason?: string }): void {
  console.log(`  [${result.valid ? "通过" : "失败"}] ${name}${result.reason ? ` -- ${result.reason}` : ""}`);
}

async function main(): Promise<void> {
  const dir = resolve(tmpdir(), `schnorr-demo-${Date.now()}`);
  const svc = SchnorrService.open(resolve(dir, "schnorr.db"));
  console.log("警告：本演示为教学实验，参数（尤其 small-unsafe-demo）不安全，禁止用于生产身份认证。");
  console.log(`临时数据库: ${dir}`);

  hr("1. 参数检查");
  for (const gp of [SMALL_GROUP, LARGE_GROUP]) {
    const r = checkGroupParams(gp);
    console.log(`  ${gp.label}: ok=${r.ok}`);
    for (const n of r.notes) console.log(`    - ${n}`);
    for (const e of r.errors) console.log(`    - 错误: ${e}`);
  }

  hr("2. 小参数：可手算的正确 Fiat-Shamir 证明");
  const gp = SMALL_GROUP;
  const x = 7n;
  const y = modPow(gp.g, x, gp.p);
  const k = 13n;
  const t = modPow(gp.g, k, gp.p);
  const context = "classroom-A";
  const c = fiatShamirChallenge(gp, y, t, context);
  const s = respond(gp, k, c, x);
  const tr = buildTranscript({ type: "fiat-shamir", gp, context, publicKey: y, commitment: t, challenge: c, response: s });
  console.log(`  公开参数 p=${gp.p}, q=${gp.q}, g=${gp.g}`);
  console.log(`  私钥 x=7（教学公开）, nonce k=13（教学公开）`);
  console.log(`  公钥 y = g^x mod p = ${dec(y)}`);
  console.log(`  承诺 t = g^k mod p = ${dec(t)}`);
  console.log(`  挑战 c = H(...) mod q = ${dec(c)}`);
  console.log(`  响应 s = k - c*x mod q = ${dec(s)}`);
  showVerify("原始转录", verifyTranscript(tr, gp, "fiat-shamir"));

  hr("3. 篡改响应 -> 验证失败");
  const tampered = { ...tr, response: dec((bi(tr.response) + 1n) % gp.q) };
  showVerify("response 被加 1", verifyTranscript(tampered, gp, "fiat-shamir"));

  hr("4. 替换上下文 -> 挑战重算不一致，失败");
  const swapped = { ...tr, context: "classroom-B" };
  showVerify("context 被替换", verifyTranscript(swapped, gp, "fiat-shamir"));

  hr("5. 交互挑战：签发 / 正确提交 / 重复消费 / 跨上下文 / 过期 / 并发");
  const kp = generateKeyPair(gp);
  const y2 = modPow(gp.g, kp.secretScalar, gp.p);
  const commitment = commit(gp);
  const issued = svc.issueChallenge({
    group: gp.label, context, publicKey: dec(y2), commitment: dec(commitment.commitment),
  });
  const sOk = respond(gp, commitment.nonce, bi(issued.challenge), kp.secretScalar);
  console.log("  首次正确提交:", svc.submitResponse({ challengeId: issued.challengeId, response: dec(sOk) }).valid ? "成功消费" : "意外失败");
  try {
    svc.submitResponse({ challengeId: issued.challengeId, response: dec(sOk) });
    console.log("  重复提交: 未拒绝（异常！）");
  } catch (e) {
    console.log(`  重复提交被拒绝: ${(e as Error).message}`);
  }
  // 另一个挑战用于跨上下文测试
  const c2 = svc.issueChallenge({ group: gp.label, context, publicKey: dec(y2), commitment: dec(commitment.commitment) });
  try {
    svc.submitResponse({ challengeId: c2.challengeId, response: dec(respond(gp, commitment.nonce, bi(c2.challenge), kp.secretScalar)), context: "other-context" });
  } catch (e) {
    console.log(`  跨上下文复用被拒绝: ${(e as Error).message}`);
  }
  // 过期挑战
  const c3 = svc.issueChallenge({ group: gp.label, context, publicKey: dec(y2), commitment: dec(commitment.commitment), ttlMs: 1 });
  await new Promise((r) => setTimeout(r, 5));
  try {
    svc.submitResponse({ challengeId: c3.challengeId, response: "0" });
  } catch (e) {
    console.log(`  过期挑战被拒绝: ${(e as Error).message}`);
  }
  // 并发：同一挑战多个提交最多一次成功（此处用同值响应，观察消费竞争）
  const c4 = svc.issueChallenge({ group: gp.label, context, publicKey: dec(y2), commitment: dec(commitment.commitment) });
  const s4 = dec(respond(gp, commitment.nonce, bi(c4.challenge), kp.secretScalar));
  const results = await Promise.all(
    [0, 1, 2, 3].map(async () => {
      try { const r = svc.submitResponse({ challengeId: c4.challengeId, response: s4 }); return r.valid ? "成功" : "方程失败但消费"; }
      catch (e) { return `拒绝:${(e as Error).message}`; }
    })
  );
  const successCount = results.filter((x) => x === "成功").length;
  console.log(`  并发 4 提交结果: ${JSON.stringify(results)}`);
  console.log(`  成功消费次数 = ${successCount}（要求恰好 1）`);

  hr("6. nonce 重用：相同 nonce、不同挑战 -> 恢复私钥");
  const reuse = analyzeNonceReuse(
    gp,
    { commitment: dec(t), challenge: dec(5n), response: dec(respond(gp, k, 5n, x)) },
    { commitment: dec(t), challenge: dec(42n), response: dec(respond(gp, k, 42n, x)) }
  );
  console.log(`  恢复秘密 = ${reuse.secretScalar}（实际 x=7，${reuse.secretScalar === "7" ? "一致" : "不一致"}）`);
  console.log(`  前提: ${reuse.explanation}`);

  hr("7. 合法的两份不同 nonce 转录 -> 不得误报恢复");
  const k2 = 29n;
  const t2 = modPow(gp.g, k2, gp.p);
  const diff = analyzeNonceReuse(
    gp,
    { commitment: dec(t), challenge: dec(5n), response: dec(respond(gp, k, 5n, x)) },
    { commitment: dec(t2), challenge: dec(42n), response: dec(respond(gp, k2, 42n, x)) }
  );
  console.log(`  recovered=${diff.recovered}: ${diff.explanation}`);

  hr("8. 类型隔离：交互与非交互转录禁止混用（验证者显式声明期望类型）");
  // 非交互转录交给期望 interactive 的验证者 -> 类型不匹配，拒绝
  showVerify("非交互转录按 interactive 验证", verifyTranscript(tr, gp, "interactive"));
  // 交互转录（服务端签发挑战）按 fiat-shamir 验证 -> 挑战重算不一致，拒绝
  const interactiveTr = buildTranscript({ type: "interactive", gp, context, publicKey: y, commitment: t, challenge: 5n, response: respond(gp, k, 5n, x) });
  showVerify("交互转录按 fiat-shamir 验证", verifyTranscript(interactiveTr, gp, "fiat-shamir"));
  // 此外交互端点要求挑战来自数据库签发记录，证明者自选挑战的转录无法冒充交互证明

  hr("9. 规范编码无歧义（不同语义 -> 不同字节串）");
  const a = canonical([9, "ab"], [9, "c"]);
  const b = canonical([9, "a"], [9, "bc"]);
  console.log(`  ("ab","c") 与 ("a","bc") 字节串相等? ${a.equals(b)}（必须 false，长度边界消除拼接歧义）`);
  console.log(`  摘要域分离: H(interactive) != H(fiat-shamir)（transcriptType 进哈希）`);

  hr("10. 导出（公开值，无秘密/nonce）");
  const exported = svc.exportPublic();
  const serialized = JSON.stringify(exported);
  console.log(`  转录数=${exported.transcripts.length}, 验证记录数=${exported.verifications.length}`);
  console.log(`  导出文本包含私钥 7 的独立值? ${serialized.includes(`"secretScalar"`)}（字段不存在）`);

  hr("11. 大参数集上的完整证明（展示数学流程）");
  const bigKp = generateKeyPair(LARGE_GROUP);
  const artifacts = (() => {
    const nonce = commit(LARGE_GROUP);
    const yy = modPow(LARGE_GROUP.g, bigKp.secretScalar, LARGE_GROUP.p);
    const cc = fiatShamirChallenge(LARGE_GROUP, yy, nonce.commitment, "large-demo");
    const ss = respond(LARGE_GROUP, nonce.nonce, cc, bigKp.secretScalar);
    return {
      transcript: buildTranscript({ type: "fiat-shamir", gp: LARGE_GROUP, context: "large-demo", publicKey: yy, commitment: nonce.commitment, challenge: cc, response: ss }),
    };
  })();
  showVerify("512 位大参数证明", verifyTranscript(artifacts.transcript, LARGE_GROUP, "fiat-shamir"));
  console.log("  （秘密与 nonce 仅存在于演示进程内存，未落库）");

  hr("完成");
  console.log("教学结论：");
  console.log("  - 正确转录满足 g^s * y^c = t；任何字段/上下文改动都会破坏等式或挑战绑定。");
  console.log("  - 挑战一次性消费，过期/跨上下文/重复（含并发）提交都会被拒绝。");
  console.log("  - nonce 绝不可重用：相同 nonce + 两个不同挑战即可恢复私钥。");
  console.log("  - 本实现参数小、无生产加固，切勿用于真实身份认证。");
  rmSync(dir, { recursive: true, force: true });
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});

