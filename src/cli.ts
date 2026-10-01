#!/usr/bin/env node
import { writeFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { loadConfig } from "./config.js";
import { getGroup, checkGroup } from "./crypto/groups.js";
import {
  PROTOCOL_VERSION,
  generateSecretKey,
  parseSecretKey,
  publicKeyFromSecret,
  proveFiatShamir,
  buildInteractiveTranscript,
  verifyTranscript,
  verifyFiatShamir,
  type SecretKey,
  type TranscriptBase,
} from "./crypto/schnorr.js";
import { analyzeNonceReuse } from "./crypto/analysis.js";
import { openDatabase } from "./server/db.js";
import { verifyImportedTranscript, transcriptJson, parseTranscriptJson } from "./server/service.js";
import {
  validHandSample,
  tamperedResponseSample,
  swappedContextSample,
  duplicateChallengeSample,
  nonceReuseSamples,
  distinctNonceSamples,
  deterministicFsSamples,
  SAMPLE_CONTEXT,
} from "./samples.js";

interface ParsedArgs {
  command: string;
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string | boolean>();
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const key = eq >= 0 ? arg.slice(2, eq) : arg.slice(2);
      if (eq >= 0) {
        flags.set(key, arg.slice(eq + 1));
      } else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) {
        flags.set(key, argv[i + 1]!);
        i++;
      } else {
        flags.set(key, true);
      }
    } else {
      positionals.push(arg);
    }
  }
  return { command: positionals[0] ?? "help", flags };
}

function flag(args: ParsedArgs, name: string, fallback?: string): string {
  const v = args.flags.get(name);
  if (typeof v === "string") return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`缺少必填参数 --${name}`);
}

function optFlag(args: ParsedArgs, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

let warned = false;
function warning(): void {
  if (warned) return;
  warned = true;
  console.log("⚠️  本程序为教学实验实现，参数小、未经审计，禁止用于生产身份认证。\n");
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  switch (args.command) {
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    case "check-params":
      warning();
      cmdCheckParams(flag(args, "group", "small-demo"));
      break;
    case "keygen":
      warning();
      cmdKeygen(flag(args, "group", "fixed-256"), optFlag(args, "secret"));
      break;
    case "demo-interactive":
      warning();
      await cmdInteractive(args);
      break;
    case "demo-fs":
      warning();
      cmdFs(args);
      break;
    case "verify":
      warning();
      cmdVerify(args);
      break;
    case "samples":
      warning();
      cmdSamples();
      break;
    case "analyze-reuse":
      warning();
      cmdAnalyzeReuse(args);
      break;
    case "config":
      console.log(JSON.stringify(loadConfig(), null, 2));
      break;
    default:
      console.error(`未知命令: ${args.command}\n`);
      printHelp();
      process.exitCode = 1;
  }
}

function printHelp(): void {
  console.log([
    "Schnorr 知识证明实验 CLI（仅教学用途，禁止用于生产身份认证）",
    "",
    "用法: schnorr-lab <命令> [参数]",
    "",
    "命令:",
    "  check-params [--group small-demo|fixed-256]",
    "  keygen --group <id> [--secret <x>]",
    "  demo-interactive [--group <id>] [--secret <x>] [--context <ctx>]",
    "  demo-fs [--group <id>] [--secret <x>] [--context <ctx>] [--out <file>]",
    "  verify --file <proof.json> [--context <ctx>] [--persist]",
    "  analyze-reuse --file-a <a.json> --file-b <b.json> [--group <id>]",
    "  samples",
    "  config",
    "",
    "环境变量: PORT(默认8787) HOST(默认127.0.0.1) DATA_DIR(默认./data) DB_FILE",
  ].join("\n"));
}

function cmdCheckParams(groupId: string): void {
  const group = getGroup(groupId);
  console.log(`参数集: ${group.id} — ${group.label}`);
  console.log(group.description);
  console.log(`p = ${group.p}`);
  console.log(`q = ${group.q}`);
  console.log(`g = ${group.g}\n`);
  const result = checkGroup(group);
  for (const c of result.checks) {
    console.log(`${c.pass ? "✅" : "❌"} ${c.name}  (${c.detail})`);
  }
  console.log(`\n总体结论: ${result.ok ? "参数检查通过" : "参数检查失败"}`);
  if (group.insecure) console.log("⚠️  该参数集离散对数可被穷举，只允许用于手算演示。");
}

function resolveSecret(groupId: string, explicit?: string): { group: ReturnType<typeof getGroup>; sk: SecretKey } {
  const group = getGroup(groupId);
  const sk = explicit ? parseSecretKey(group, BigInt(explicit)) : generateSecretKey(group);
  return { group, sk };
}

function cmdKeygen(groupId: string, explicit?: string): void {
  const { group, sk } = resolveSecret(groupId, explicit);
  const pk = publicKeyFromSecret(group, sk);
  console.log("本地密钥材料（不写入数据库/日志；请自行安全保存 secretX）:");
  console.log(JSON.stringify({ groupId: group.id, secretX: sk.x.toString(), publicY: pk.y.toString() }, null, 2));
}

async function cmdInteractive(args: ParsedArgs): Promise<void> {
  const groupId = flag(args, "group", "small-demo");
  const context = flag(args, "context", SAMPLE_CONTEXT);
  const { group, sk } = resolveSecret(groupId, optFlag(args, "secret"));
  const pk = publicKeyFromSecret(group, sk);
  const { issueChallenge, submitInteractiveResponse } = await import("./server/service.js");
  const { commit } = await import("./crypto/schnorr.js");
  const config = loadConfig();
  const db = openDatabase(config.dbFile);
  try {
    const commitmentObj = commit(group);
    const issued = issueChallenge(db, {
      groupId: group.id,
      context,
      y: pk.y,
      commitment: commitmentObj.commitment,
    });
    const transcript = buildInteractiveTranscript(group, sk, context, commitmentObj, issued.challenge);
    console.log("公开转录:");
    console.log(JSON.stringify(transcriptJson(transcript), null, 2));
    const first = submitInteractiveResponse(db, { challengeId: issued.challengeId, response: transcript.response });
    console.log("\n第一次提交:", JSON.stringify({ valid: first.valid, reason: first.reason ?? null }));
    const second = submitInteractiveResponse(db, { challengeId: issued.challengeId, response: transcript.response });
    console.log("重复提交:  ", JSON.stringify({ valid: second.valid, reason: second.reason ?? null }));
  } finally {
    db.close();
  }
}

function cmdFs(args: ParsedArgs): void {
  const groupId = flag(args, "group", "small-demo");
  const context = flag(args, "context", SAMPLE_CONTEXT);
  const { group, sk } = resolveSecret(groupId, optFlag(args, "secret"));
  const transcript = proveFiatShamir(group, sk, context);
  const json = transcriptJson(transcript);
  console.log("Fiat-Shamir 公开转录（无私钥/nonce）:");
  console.log(JSON.stringify(json, null, 2));
  const result = verifyFiatShamir(group, transcript);
  console.log(`\n自验证: ${result.valid ? "✅ 通过" : "❌ 失败 " + result.reason}`);
  const out = optFlag(args, "out");
  if (out) {
    writeFileSync(resolve(out), JSON.stringify(json, null, 2), "utf8");
    console.log(`已导出: ${resolve(out)}`);
  }
}

function cmdVerify(args: ParsedArgs): void {
  const file = flag(args, "file");
  const expectedContext = optFlag(args, "context");
  const raw = JSON.parse(readFileSync(resolve(file), "utf8")) as unknown;
  const parsed: TranscriptBase = parseTranscriptJson(raw);
  const group = getGroup(parsed.groupId);
  const result = verifyTranscript(group, parsed, expectedContext ?? parsed.context);
  console.log(`${result.valid ? "✅ 验证通过" : "❌ 验证失败"}${result.reason ? "：" + result.reason : ""}`);
  if (args.flags.get("persist")) {
    const config = loadConfig();
    const db = openDatabase(config.dbFile);
    try {
      const saved = verifyImportedTranscript(db, { transcript: raw, expectedContext });
      console.log("已写入验证记录:", saved.transcriptId ?? "(交互转录不重新入库)");
    } finally {
      db.close();
    }
  }
  if (!result.valid) process.exitCode = 2;
}

function cmdAnalyzeReuse(args: ParsedArgs): void {
  const group = getGroup(flag(args, "group", "small-demo"));
  const a = parseTranscriptJson(JSON.parse(readFileSync(resolve(flag(args, "file-a")), "utf8")));
  const b = parseTranscriptJson(JSON.parse(readFileSync(resolve(flag(args, "file-b")), "utf8")));
  const result = analyzeNonceReuse(group, a, b);
  console.log(result.explanation);
  console.log(
    JSON.stringify(
      {
        reuseDetected: result.reuseDetected,
        reason: result.reason ?? null,
        recoveredX: result.recoveredX?.toString() ?? null,
        publicKeyMatches: result.publicKeyMatches ?? null,
      },
      null,
      2,
    ),
  );
}

function cmdSamples(): void {
  const group = getGroup("small-demo");
  const show = (title: string, sample: { name: string; description: string; transcript: TranscriptBase }, context?: string) => {
    const result = verifyTranscript(group, sample.transcript, context ?? sample.transcript.context);
    console.log(`\n=== ${title}（${sample.name}）===`);
    console.log(sample.description);
    console.log(JSON.stringify(transcriptJson(sample.transcript)));
    console.log(`验证: ${result.valid ? "✅ 通过" : "❌ " + result.reason}`);
  };

  show("可手算正确证明", validHandSample());
  show("被修改的响应", tamperedResponseSample());
  show("替换上下文（按原上下文验证）", swappedContextSample(), SAMPLE_CONTEXT);
  show("重复挑战样本（单独验证有效；提交由一次性消费拦截）", duplicateChallengeSample());

  const fsSamples = deterministicFsSamples();
  const fsValid = verifyFiatShamir(group, fsSamples.valid);
  const fsWrong = verifyFiatShamir(group, fsSamples.wrongContext, SAMPLE_CONTEXT);
  console.log("\n=== 确定性 Fiat-Shamir 样本 ===");
  console.log("正确:", JSON.stringify(transcriptJson(fsSamples.valid)));
  console.log("结果:", fsValid.valid ? "✅ 通过" : "❌ " + fsValid.reason);
  console.log("替换上下文后按原上下文验证:", fsWrong.valid ? "✅" : "❌ " + fsWrong.reason);

  const reuse = nonceReuseSamples();
  const reuseResult = analyzeNonceReuse(group, reuse.first, reuse.second);
  console.log("\n=== Nonce 重用分析 ===");
  console.log("转录 A:", JSON.stringify(transcriptJson(reuse.first)));
  console.log("转录 B:", JSON.stringify(transcriptJson(reuse.second)));
  console.log(reuseResult.explanation);
  console.log("恢复的私钥:", reuseResult.recoveredX?.toString(), "| 与 g^x=y 一致:", reuseResult.publicKeyMatches);

  const distinct = distinctNonceSamples();
  const distinctResult = analyzeNonceReuse(group, distinct.first, distinct.second);
  console.log("\n=== 不同 nonce 对照（不得误报）===");
  console.log(distinct.explanation);
  console.log("分析结论:", distinctResult.reuseDetected ? "❌ 误报！" : "✅ 未报告重用", "|", distinctResult.reason);
}

void PROTOCOL_VERSION;

main().catch((err: Error) => {
  console.error("错误:", err.message);
  process.exit(1);
});
