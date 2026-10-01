// 纯 Node HTTP API 服务（无第三方框架）。
// 安全约定：任何响应、日志、导出都不返回私有标量与 nonce。
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import { SchnorrService, ServiceError } from "./service.js";
import { getGroup } from "./params.js";
import { bi, commit, dec, generateKeyPair, proveNonInteractive, type Transcript } from "./proof.js";

export interface ServerConfig {
  port: number;
  dataDir: string;
}

export function readJson(req: IncomingMessage, maxBytes = 1_000_000): Promise<unknown> {
  return new Promise((resolveJson, rejectJson) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        rejectJson(new ServiceError(413, "请求体过大"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (raw.length === 0) return resolveJson({});
      try { resolveJson(JSON.parse(raw)); } catch { rejectJson(new ServiceError(400, "JSON 解析失败")); }
    });
    req.on("error", rejectJson);
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

export function createApp(service: SchnorrService): Server {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    // 安全日志：只记录方法、路径与状态，绝不记录请求体中的秘密字段
    const logLine = (status: number) =>
      console.log(`${new Date().toISOString()} ${method} ${path} -> ${status}`);

    try {
      if (method === "GET" && path === "/health") {
        send(res, 200, { ok: true, service: "schnorr-teaching", warning: "仅限教学，禁止用于生产身份认证" });
        logLine(200); return;
      }

      if (method === "GET" && path === "/api/groups") {
        send(res, 200, { groups: service.listGroups() });
        logLine(200); return;
      }

      const groupMatch = path.match(/^\/api\/groups\/([^/]+)\/check$/);
      if (method === "GET" && groupMatch) {
        const check = service.checkGroup(decodeURIComponent(groupMatch[1]!));
        send(res, 200, check);
        logLine(200); return;
      }

      if (method === "POST" && path === "/api/proofs/demo") {
        // 本地演示：在服务端临时生成秘密并回显，便于课堂演示。
        // 秘密不落库、不进日志；真实使用请用 CLI 本地持有私钥。
        const body = (await readJson(req)) as { group?: string; context?: string; secretScalar?: string };
        const label = body.group ?? "small-unsafe-demo";
        const gp = getGroup(label);
        let x: bigint;
        if (body.secretScalar !== undefined) {
          x = bi(body.secretScalar);
          if (x <= 0n || x >= gp.q) throw new ServiceError(400, "secretScalar 必须在 [1,q-1]");
        } else {
          x = generateKeyPair(gp).secretScalar;
        }
        const context = body.context ?? "demo-context";
        const artifacts = proveNonInteractive(gp, x, context);
        service.saveNonInteractive(artifacts.transcript, "api");
        send(res, 200, {
          note: "教学演示：secretScalar/nonce 仅本次响应返回，服务器不保存",
          secretScalar: artifacts.secretScalar,
          nonce: artifacts.nonce,
          transcript: artifacts.transcript,
        });
        logLine(200); return;
      }

      if (method === "POST" && path === "/api/proofs/non-interactive") {
        // 保存已生成的非交互公开转录（例如 CLI 在本地用私钥生成后上传公开部分）
        const tr = (await readJson(req)) as Transcript;
        const id = service.saveNonInteractive(sanitizeTranscript(tr), "api");
        send(res, 200, { transcriptId: id, transcript: tr });
        logLine(200); return;
      }

      if (method === "POST" && path === "/api/challenges") {
        const body = (await readJson(req)) as {
          group?: string; context?: string; publicKey?: string; commitment?: string; ttlMs?: number;
        };
        if (!body.group || !body.context || !body.publicKey || !body.commitment) {
          throw new ServiceError(400, "需要 group, context, publicKey, commitment");
        }
        const out = service.issueChallenge({
          group: body.group,
          context: body.context,
          publicKey: body.publicKey,
          commitment: body.commitment,
          ttlMs: body.ttlMs,
        });
        send(res, 201, out);
        logLine(201); return;
      }

      if (method === "POST" && path === "/api/challenges/submit") {
        const body = (await readJson(req)) as { challengeId?: string; response?: string; context?: string };
        if (!body.challengeId || body.response === undefined) {
          throw new ServiceError(400, "需要 challengeId 与 response");
        }
        const out = service.submitResponse({
          challengeId: body.challengeId, response: body.response, context: body.context,
        });
        send(res, 200, out);
        logLine(200); return;
      }

      if (method === "POST" && path === "/api/verify") {
        const tr = sanitizeTranscript((await readJson(req)) as Transcript);
        const out = service.offlineVerify(tr);
        send(res, out.valid ? 200 : 422, out);
        logLine(out.valid ? 200 : 422); return;
      }

      if (method === "POST" && path === "/api/commitment") {
        // 便利接口：生成承诺。注意 nonce 必须由证明者本地持有；
        // 此接口返回 nonce 仅用于本地实验，服务器不保存它。
        const body = (await readJson(req)) as { group?: string; publicKey?: string };
        const gp = getGroup(body.group ?? "small-unsafe-demo");
        const { nonce, commitment } = commit(gp);
        send(res, 200, {
          note: "nonce 仅本次返回且服务器不保存；生产方案应由证明者本地生成",
          nonce: dec(nonce),
          commitment: dec(commitment),
          group: gp.label,
        });
        logLine(200); return;
      }

      if (method === "POST" && path === "/api/analysis/nonce-reuse") {
        const body = (await readJson(req)) as { group?: string };
        const out = service.analyzeNonceReuseSamples(body.group ?? "small-unsafe-demo");
        send(res, 200, out);
        logLine(200); return;
      }

      if (method === "GET" && path === "/api/transcripts") {
        send(res, 200, { transcripts: service.listTranscripts() });
        logLine(200); return;
      }

      if (method === "GET" && path === "/api/verifications") {
        send(res, 200, { verifications: service.listVerifications() });
        logLine(200); return;
      }

      if (method === "GET" && path === "/api/challenges") {
        // 只返回公开状态，不附带秘密
        send(res, 200, { challenges: service.listChallenges() });
        logLine(200); return;
      }

      if (method === "GET" && path === "/api/export") {
        send(res, 200, service.exportPublic());
        logLine(200); return;
      }

      send(res, 404, { error: "未找到", path });
      logLine(404);
    } catch (err) {
      if (err instanceof ServiceError) {
        send(res, err.status, { error: err.message });
        logLine(err.status);
        return;
      }
      console.error("服务器错误:", err instanceof Error ? err.message : err);
      send(res, 500, { error: "内部错误" });
      logLine(500);
    }
  });
  return server;
}

function sanitizeTranscript(tr: Transcript): Transcript {
  // 显式白名单字段，防止多余字段携带秘密被误存
  return {
    version: tr.version,
    transcriptType: tr.transcriptType,
    groupLabel: tr.groupLabel,
    context: tr.context,
    publicKey: tr.publicKey,
    commitment: tr.commitment,
    challenge: tr.challenge,
    response: tr.response,
  };
}

function parseArgs(argv: string[]): ServerConfig {
  let port = Number(process.env.PORT ?? 3000);
  let dataDir = process.env.DATA_DIR ?? resolve(process.cwd(), "data");
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--port" && argv[i + 1]) port = Number(argv[++i]);
    else if (a === "--data-dir" && argv[i + 1]) dataDir = resolve(argv[++i]!);
  }
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error("非法端口");
  return { port, dataDir };
}

if (require.main === module) {
  const cfg = parseArgs(process.argv.slice(2));
  const service = SchnorrService.open(resolve(cfg.dataDir, "schnorr.db"));
  const server = createApp(service);
  server.listen(cfg.port, () => {
    console.log(`Schnorr 教学服务已启动: http://localhost:${cfg.port}`);
    console.log(`数据目录: ${cfg.dataDir}`);
    console.log("警告：本服务为教学实验，不安全，禁止用于生产身份认证。");
  });
}

