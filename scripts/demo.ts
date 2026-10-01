/**
 * 端到端教学演示：
 *   1. 启动内存式 SQLite 的同一套服务代码（这里通过 HTTP 调用真实接口）；
 *   2. 交互式证明：通过 / 篡改 / 重放 / 过期 / 并发一次性消费；
 *   3. Fiat-Shamir 非交互证明：正常 / 替换上下文 / 篡改响应；
 *   4. nonce 重用恢复私钥，以及不同 nonce 不误报；
 *   5. 导出公开数据，确认不含秘密字段。
 *
 * 运行：npm run demo
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApiServer } from "../src/server/http.js";
import { openDatabase } from "../src/server/db.js";
import { getGroup } from "../src/crypto/groups.js";
import {
  generateSecretKey,
  publicKeyFromSecret,
  commit,
  buildInteractiveTranscript,
  proveFiatShamir,
  verifyFiatShamir,
} from "../src/crypto/schnorr.js";
import { analyzeNonceReuse } from "../src/crypto/analysis.js";
import { transcriptJson } from "../src/server/service.js";

const SMALL = getGroup("small-demo");

async function main(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "schnorr-demo-"));
  const db = openDatabase(join(dir, "demo.sqlite"));
  const server = createApiServer({ db });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("无法获取演示端口");
  const base = `http://127.0.0.1:${address.port}`;

  console.log("⚠️  教学实验演示，禁止用于生产身份认证。\n");

  // ---------- 1. 参数检查 ----------
  const check = await api("GET", `${base}/api/groups/small-demo/check`);
  console.log("【1】参数检查 small-demo:", check.ok ? "通过" : "失败");

  // ---------- 2. 交互式证明 ----------
  const context = "demo-context-2026";
  const sk = generateSecretKey(SMALL);
  const pk = publicKeyFromSecret(SMALL, sk);
  const commitmentObj = commit(SMALL);
  console.log("\n【2】交互式 Schnorr 证明");
  console.log("公开 y =", pk.y.toString(), " R =", commitmentObj.commitment.toString());

  const issued = await api<{ challengeId: string; challenge: string; expiresAt: number }>(
    "POST",
    `${base}/api/challenges`,
    {
      groupId: SMALL.id,
      context,
      y: pk.y.toString(),
      commitment: commitmentObj.commitment.toString(),
      ttlMs: 60000,
    },
  );
  console.log("服务端签发挑战 c =", issued.challenge, "（id 隐藏在客户端提交中）");
  const transcript = buildInteractiveTranscript(SMALL, sk, context, commitmentObj, BigInt(issued.challenge));

  const good = await api("POST", `${base}/api/challenges/${issued.challengeId}/submit`, {
    response: transcript.response.toString(),
  });
  console.log("正确响应提交:", good.valid ? "✅ 成功" : "❌ " + good.reason);

  const replay = await api("POST", `${base}/api/challenges/${issued.challengeId}/submit`, {
    response: transcript.response.toString(),
  });
  console.log("同挑战重放:  ", replay.valid ? "❌ 不应成功" : "✅ 被拒绝（" + replay.reason + "）");

  // 篡改响应
  const c2 = await issueChallenge(base, pk.y.toString(), commitmentObj.commitment.toString(), context, 2000);
  const tampered = await api("POST", `${base}/api/challenges/${c2.id}/submit`, {
    response: ((transcript.response + 1n) % SMALL.q).toString(),
  });
  console.log("篡改响应:    ", tampered.valid ? "❌ 误判" : "✅ 验证失败（" + tampered.reason + "），挑战仍被一次性消费");

  // 过期挑战
  const c3 = await issueChallenge(base, pk.y.toString(), commitmentObj.commitment.toString(), context, 50);
  await sleep(120);
  const expired = await api("POST", `${base}/api/challenges/${c3.id}/submit`, {
    response: transcript.response.toString(),
  });
  console.log("过期后提交:  ", expired.valid ? "❌ 误判" : "✅ 被拒绝（" + expired.reason + "）");

  // 并发：同一挑战同时提交两次，最多一次成功
  const c4 = await issueChallenge(base, pk.y.toString(), commitmentObj.commitment.toString(), context, 60000);
  const t4 = buildInteractiveTranscript(SMALL, sk, context, commitmentObj, BigInt(c4.challenge));
  const [r1, r2] = await Promise.all([
    api("POST", `${base}/api/challenges/${c4.id}/submit`, { response: t4.response.toString() }),
    api("POST", `${base}/api/challenges/${c4.id}/submit`, { response: t4.response.toString() }),
  ]);
  console.log("并发两次提交: 成功数 =", Number(r1.valid) + Number(r2.valid), "（要求恰好为 1）");

  // ---------- 3. Fiat-Shamir ----------
  console.log("\n【3】Fiat-Shamir 非交互证明");
  const fsProof = proveFiatShamir(SMALL, sk, context);
  const fsRes = await api("POST", `${base}/api/verify`, { transcript: transcriptJson(fsProof), expectedContext: context });
  console.log("正常 FS 证明:", fsRes.valid ? "✅ 通过" : "❌ " + fsRes.reason);

  const swapped = { ...transcriptJson(fsProof), context: "evil-context" };
  const swapRes = await api("POST", `${base}/api/verify`, { transcript: swapped, expectedContext: context });
  console.log("替换上下文:  ", swapRes.valid ? "❌ 误判" : "✅ 拒绝（" + swapRes.reason + "）");

  const tamperedFs = { ...transcriptJson(fsProof), response: ((fsProof.response + 1n) % SMALL.q).toString() };
  const tamperRes = await api("POST", `${base}/api/verify`, { transcript: tamperedFs });
  console.log("篡改 FS 响应:", tamperRes.valid ? "❌ 误判" : "✅ 拒绝（" + tamperRes.reason + "）");

  // 交互/非交互混用：把 FS 转录伪装成交互类型
  const mixed = { ...transcriptJson(fsProof), kind: "interactive" };
  const mixedRes = await api("POST", `${base}/api/verify`, { transcript: mixed });
  console.log("类型混用:    ", mixedRes.status === 200 && mixedRes.valid ? "❌ 误判" : "✅ 拒绝（" + (mixedRes.reason ?? mixedRes.error) + "）");

  // 离线本地验证大参数
  const fixed = getGroup("fixed-256");
  const sk256 = generateSecretKey(fixed);
  const fs256 = proveFiatShamir(fixed, sk256, "fixed-param-flow");
  console.log("\n固定 256 位参数 FS 证明离线验证:", verifyFiatShamir(fixed, fs256).valid ? "✅ 通过" : "❌");

  // ---------- 4. nonce 重用 ----------
  console.log("\n【4】nonce 重用 -> 恢复私钥");
  const reuseNonce = commit(SMALL);
  const chA = await issueChallenge(base, pk.y.toString(), reuseNonce.commitment.toString(), context, 60000);
  const chB = await issueChallenge(base, pk.y.toString(), reuseNonce.commitment.toString(), context, 60000);
  const ta = buildInteractiveTranscript(SMALL, sk, context, reuseNonce, BigInt(chA.challenge));
  const tb = buildInteractiveTranscript(SMALL, sk, context, reuseNonce, BigInt(chB.challenge));
  const analysis = analyzeNonceReuse(SMALL, ta, tb);
  console.log("重用检测:", analysis.reuseDetected ? "✅ 检出" : "❌ 漏报");
  console.log(analysis.explanation);
  console.log("恢复值等于真实私钥:", analysis.recoveredX === sk.x ? "✅" : "❌");

  const safe1 = buildInteractiveTranscript(SMALL, sk, context, commit(SMALL), 2n);
  const safe2 = buildInteractiveTranscript(SMALL, sk, context, commit(SMALL), 5n);
  const safeAnalysis = analyzeNonceReuse(SMALL, safe1, safe2);
  console.log("不同 nonce 对照:", safeAnalysis.reuseDetected ? "❌ 误报" : "✅ 未误报（" + safeAnalysis.reason + "）");

  // ---------- 5. 导出 ----------
  const exported = await api("GET", `${base}/api/export`);
  const exportedText = JSON.stringify(exported);
  console.log("\n【5】公开导出包含秘密字段?", /secretX|"x"|nonce/.test(exportedText) ? "❌ 包含！" : "✅ 不包含");
  console.log("导出转录条数:", exported.transcripts.length, " 验证记录条数:", exported.verifications.length);

  server.close();
  db.close();
  console.log("\n演示结束。再次强调：这是教学代码，不能用于真实身份认证。");
}

async function issueChallenge(
  base: string,
  y: string,
  commitment: string,
  context: string,
  ttlMs: number,
): Promise<{ id: string; challenge: string }> {
  const res = await api<{ challengeId: string; challenge: string }>("POST", `${base}/api/challenges`, {
    groupId: SMALL.id,
    context,
    y,
    commitment,
    ttlMs,
  });
  return { id: res.challengeId, challenge: res.challenge };
}

async function api<T = any>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = (await res.json()) as T;
  if (!res.ok) return { ...(json as object), status: res.status } as T;
  return json;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
