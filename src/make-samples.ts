// 生成教学样本（小参数 p=607,q=101,g=7，x=7,k=13）到 samples/ 目录：
// 正确证明、被改响应、替换上下文、重复挑战、nonce 重用两份转录。
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { SMALL_GROUP } from "./params.js";
import { bi, buildTranscript, dec, fiatShamirChallenge, respond } from "./proof.js";
import { modPow } from "./bignum.js";

const gp = SMALL_GROUP;
const x = 7n, k = 13n;
const y = modPow(gp.g, x, gp.p);
const t = modPow(gp.g, k, gp.p);
const context = "classroom-A";
const c = fiatShamirChallenge(gp, y, t, context);
const s = respond(gp, k, c, x);

const base = buildTranscript({ type: "fiat-shamir", gp, context, publicKey: y, commitment: t, challenge: c, response: s });
const tampered = { ...base, response: dec((s + 1n) % gp.q) };
const swappedContext = { ...base, context: "classroom-B" };

// 交互样本：同一挑战（服务端签发的 c=5），重复提交演示
const cInt = 5n;
const sInt = respond(gp, k, cInt, x);
const interactive1 = buildTranscript({ type: "interactive", gp, context, publicKey: y, commitment: t, challenge: cInt, response: sInt });
const interactiveDuplicate = { ...interactive1, note: "同一挑战 id 的第二次提交应被服务拒绝（一次性消费）" };

// nonce 重用：相同 t（=相同 k）、不同挑战 5 与 42
const c1 = 5n, c2 = 42n;
const reuse1 = buildTranscript({ type: "interactive", gp, context: "nonce-reuse-demo", publicKey: y, commitment: t, challenge: c1, response: respond(gp, k, c1, x) });
const reuse2 = buildTranscript({ type: "interactive", gp, context: "nonce-reuse-demo", publicKey: y, commitment: t, challenge: c2, response: respond(gp, k, c2, x) });

const dir = resolve(process.cwd(), "samples");
mkdirSync(dir, { recursive: true });
const files: Array<[string, unknown]> = [
  ["01-valid-fiat-shamir.json", { note: "正确非交互证明", transcript: base, handCalc: { p: 607, q: 101, g: 7, x: 7, k: 13, y: dec(y), t: dec(t), c: dec(c), s: dec(s) } }],
  ["02-tampered-response.json", { note: "响应被加 1，验证方程失败", transcript: tampered }],
  ["03-swapped-context.json", { note: "上下文替换为 classroom-B，Fiat-Shamir 挑战不匹配", transcript: swappedContext }],
  ["04-interactive-challenge-first.json", { note: "交互挑战首次提交（服务端需有对应待消费挑战）", transcript: interactive1 }],
  ["05-interactive-challenge-duplicate.json", { note: "重复挑战/重放：服务端必须以 409 拒绝", transcript: interactiveDuplicate }],
  ["06-nonce-reuse-a.json", { note: "nonce 重用样本 A：相同承诺 t，挑战 5", transcript: reuse1 }],
  ["07-nonce-reuse-b.json", { note: "nonce 重用样本 B：相同承诺 t，挑战 42；与 A 联立恢复 x=7", transcript: reuse2 }],
];
for (const [name, data] of files) {
  writeFileSync(resolve(dir, name), JSON.stringify(data, null, 2), "utf8");
  console.log("写出 samples/" + name);
}
