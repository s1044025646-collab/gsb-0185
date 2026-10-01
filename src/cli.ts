#!/usr/bin/env node
// 命令行界面：本地生成私钥/证明、离线验证、挑战交互、导入导出与 nonce 重用分析。
// 私钥默认只存在内存；--save-secret 会显式写入本地文件（默认不保存）。
import { resolve } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { SchnorrService } from "./service.js";
import { getGroup, checkGroupParams } from "./params.js";
import {
  bi, dec, commit, fiatShamirChallenge, generateKeyPair,
  respond, verifyTranscript, buildTranscript, analyzeNonceReuse,
} from "./proof.js";
import { modPow } from "./bignum.js";

interface CliFlags {
  group: string;
  context: string;
  dataDir: string;
  out?: string;
  in?: string;
  secret?: string;
  nonce?: string;
  saveSecret?: string;
  url?: string;
  ttlMs?: number;
}

function parseFlags(argv: string[]): { command: string; flags: CliFlags } {
  const flags: CliFlags = {
    group: "small-unsafe-demo",
    context: "cli-context",
    dataDir: process.env.DATA_DIR ?? resolve(process.cwd(), "data"),
  };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} 缺少参数`);
      return v;
    };
    if (a === "--group") flags.group = next();
    else if (a === "--context") flags.context = next();
    else if (a === "--data-dir") flags.dataDir = resolve(next());
    else if (a === "--out") flags.out = next();
    else if (a === "--in") flags.in = next();
    else if (a === "--secret") flags.secret = next();
    else if (a === "--nonce") flags.nonce = next();
    else if (a === "--save-secret") flags.saveSecret = next();
    else if (a === "--url") flags.url = next();
    else if (a === "--ttl-ms") flags.ttlMs = Number(next());
    else rest.push(a);
  }
  return { command: rest[0] ?? "help", flags };
}

function out(value: unknown, file?: string): void {
  const text = JSON.stringify(value, null, 2);
  if (file) { writeFileSync(file, text, "utf8"); console.log(`已写入 ${file}`); }
  else console.log(text);
}

function service(flags: CliFlags): SchnorrService {
  return SchnorrService.open(resolve(flags.dataDir, "schnorr.db"));
}

async function main(): Promise<void> {
  const { command, flags } = parseFlags(process.argv.slice(2));
  const gp = getGroupSafe(flags.group);

  switch (command) {
    case "help":
    case "--help":
    case "-h": {
      printHelp();
      return;
    }

    case "groups": {
      const svc = service(flags);
      out({ groups: svc.listGroups() });
      return;
    }

    case "check-params": {
      out({ group: gp.label, ...checkGroupParams(gp) });
      return;
    }

    case "keygen": {
      const { secretScalar, publicKey } = generateKeyPair(gp);
      const result = {
        warning: "秘密标量仅本地显示，服务与数据库默认不保存",
        group: gp.label,
        publicKey: dec(publicKey),
        secretScalar: dec(secretScalar),
      };
      if (flags.saveSecret) {
        writeFileSync(flags.saveSecret, JSON.stringify({ group: gp.label, secretScalar: dec(secretScalar) }, null, 2), "utf8");
        console.error(`私钥已显式保存到 ${flags.saveSecret}（请自行保管，勿提交到版本库）`);
      }
      out(result, flags.out);
      return;
    }

    case "prove": {
      if (!flags.secret) throw new Error("prove 需要 --secret <私有标量>");
      const x = bi(flags.secret);
      const y = modPow(gp.g, x, gp.p);
      const k = flags.nonce !== undefined ? bi(flags.nonce) : commit(gp).nonce;
      if (k <= 0n || k >= gp.q) throw new Error("--nonce 必须在 [1,q-1]");
      const t = modPow(gp.g, k, gp.p);
      const c = fiatShamirChallenge(gp, y, t, flags.context);
      const s = respond(gp, k, c, x);
      const transcript = buildTranscript({ type: "fiat-shamir", gp, context: flags.context, publicKey: y, commitment: t, challenge: c, response: s });
      // 转录入库（公开值）；秘密与 nonce 不写入
      const svc = service(flags);
      const id = svc.saveNonInteractive(transcript, "cli");
      out({
        transcriptId: id,
        transcript,
        localOnly: { nonce: dec(k) },
        note: "localOnly.nonce 仅在本次命令输出；数据库不保存 nonce 与私钥",
      }, flags.out);
      return;
    }

    case "verify": {
      const file = flags.in ?? (flags.out ? undefined : undefined);
      void file;
      if (!flags.in) throw new Error("verify 需要 --in <transcript.json>");
      const loaded = JSON.parse(readFileSync(flags.in, "utf8"));
      const tr = (loaded.transcript ?? loaded) as Parameters<typeof verifyTranscript>[0];
      const gp2 = getGroup(tr.groupLabel);
      const expected = tr.transcriptType === "fiat-shamir" ? "fiat-shamir" : "interactive";
      const result = verifyTranscript(tr, gp2, expected);
      out({ input: flags.in, ...result });
      if (!result.valid) process.exitCode = 2;
      return;
    }

    case "interactive": {
      // 与运行中的服务做交互式三段流程（可选用 --url）
      if (!flags.secret) throw new Error("interactive 需要 --secret");
      const base = flags.url ?? "http://localhost:3000";
      const x = bi(flags.secret);
      const y = modPow(gp.g, x, gp.p);
      const { nonce, commitment } = commit(gp);
      const issued = await http<{ challengeId: string; challenge: string }>(`${base}/api/challenges`, {
        method: "POST", body: { group: gp.label, context: flags.context, publicKey: dec(y), commitment: dec(commitment), ttlMs: flags.ttlMs },
      });
      const s = respond(gp, nonce, bi(issued.challenge), x);
      const result = await http<{ valid: boolean; reason: string | null }>(`${base}/api/challenges/submit`, {
        method: "POST", body: { challengeId: issued.challengeId, response: dec(s), context: flags.context },
      });
      out({ publicKey: dec(y), commitment: dec(commitment), challenge: issued.challenge, response: dec(s), result });
      return;
    }

    case "export": {
      out(service(flags).exportPublic(), flags.out);
      return;
    }

    case "import": {
      if (!flags.in) throw new Error("import 需要 --in <transcript.json>");
      const loaded = JSON.parse(readFileSync(flags.in, "utf8"));
      const tr = (loaded.transcript ?? loaded) as Parameters<SchnorrService["offlineVerify"]>[0];
      const result = service(flags).offlineVerify(tr);
      out(result);
      if (!result.valid) process.exitCode = 2;
      return;
    }

    case "nonce-reuse": {
      if (!gp.unsafeSmall) throw new Error("nonce-reuse 仅支持小参数集");
      const x = 7n, k = 13n, c1 = 5n, c2 = 42n;
      const t = modPow(gp.g, k, gp.p);
      const s1 = respond(gp, k, c1, x);
      const s2 = respond(gp, k, c2, x);
      const reuse = analyzeNonceReuse(gp,
        { commitment: dec(t), challenge: dec(c1), response: dec(s1) },
        { commitment: dec(t), challenge: dec(c2), response: dec(s2) });
      out({ commitment: dec(t), c1: dec(c1), s1: dec(s1), c2: dec(c2), s2: dec(s2), ...reuse, expectedSecret: dec(x) });
      return;
    }

    case "list": {
      const svc = service(flags);
      out({ transcripts: svc.listTranscripts(), verifications: svc.listVerifications() });
      return;
    }

    default:
      console.error(`未知命令: ${command}`);
      printHelp();
      process.exitCode = 1;
  }
}

function getGroupSafe(label: string) {
  return getGroup(label);
}

async function http<T>(url: string, init: { method: string; body: unknown }): Promise<T> {
  const res = await fetch(url, {
    method: init.method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(init.body),
  });
  const data = (await res.json()) as T & { error?: string };
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${data.error ?? "请求失败"}`);
  return data as T;
}

function printHelp(): void {
  console.log(`Schnorr 教学实验 CLI（仅限教学，禁止生产用途）

用法: schnorr-demo <命令> [选项]

命令:
  groups              列出公开参数集及参数检查结果
  check-params        检查当前参数集的素性、子群阶与生成元
  keygen              本地生成密钥对（默认只在屏幕显示私钥，不入库）
                      --save-secret <file>  显式把私钥写入本地文件
  prove               用 --secret 生成 Fiat-Shamir 非交互证明（公开转录入库）
                      --nonce <k>          显式指定 nonce（仅测试用）
  verify --in <file>  离线验证转录文件
  interactive         对运行中的服务完成交互三段流程（--url 指定地址）
  nonce-reuse         小参数：演示相同 nonce 不同挑战下恢复私钥
  export              导出全部公开转录与验证记录（不含秘密）
  import --in <file>  导入转录并离线验证、入库记录
  list                列出本地库中的转录与验证记录

选项:
  --group <label>     small-unsafe-demo（默认，不安全） | fixed-large-512
  --context <string>  上下文/域分离标签（默认 cli-context）
  --data-dir <dir>    数据目录（默认 ./data）
  --out <file>        把 JSON 结果写入文件
  --in <file>         输入转录 JSON
  --secret <x>        私有标量（请仅在本地安全环境提供）
  --url <base>        交互命令的服务地址（默认 http://localhost:3000）
  --ttl-ms <n>        交互挑战有效期
`);
}

main().catch((err: unknown) => {
  console.error("错误:", err instanceof Error ? err.message : err);
  process.exit(1);
});

