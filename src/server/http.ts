/**
 * 纯 Node http 实现的 JSON API。无第三方框架。
 * 所有响应只包含公开数据，绝不返回私钥/nonce。
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { DatabaseSync } from "node:sqlite";
import { listGroups } from "./db.js";
import {
  NotFoundError,
  ValidationError,
  getPublicData,
  getTranscripts,
  getVerifications,
  groupCheckInfo,
  issueChallenge,
  parseTranscriptJson,
  submitInteractiveResponse,
  verifyImportedTranscript,
  transcriptJson,
} from "./service.js";

export interface ApiDeps {
  db: DatabaseSync;
}

interface Route {
  method: string;
  pattern: RegExp;
  handler: (deps: ApiDeps, body: unknown, params: string[], query: URL) => Promise<unknown> | unknown;
}

const routes: Route[] = [
  { method: "GET", pattern: /^\/api\/health$/, handler: () => ({ status: "ok", service: "schnorr-proof-lab" }) },
  {
    method: "GET",
    pattern: /^\/api\/groups$/,
    handler: (deps) => ({ groups: listGroups(deps.db) }),
  },
  {
    method: "GET",
    pattern: /^\/api\/groups\/([^/]+)\/check$/,
    handler: (_deps, _b, params) => groupCheckInfo(params[0]!),
  },
  {
    method: "POST",
    pattern: /^\/api\/challenges$/,
    handler: (deps, body) => {
      const b = asObject(body);
      const res = issueChallenge(deps.db, {
        groupId: requireString(b, "groupId"),
        context: requireString(b, "context"),
        y: requireBigInt(b, "y"),
        commitment: requireBigInt(b, "commitment"),
        ttlMs: b.ttlMs === undefined ? undefined : requireInt(b, "ttlMs"),
      });
      return {
        challengeId: res.challengeId,
        challenge: res.challenge.toString(),
        expiresAt: res.expiresAt,
        note: "挑战一次性、带过期时间，重复或过期提交会被拒绝",
      };
    },
  },
  {
    method: "POST",
    pattern: /^\/api\/challenges\/([^/]+)\/submit$/,
    handler: (deps, body, params) => {
      const b = asObject(body);
      return submitInteractiveResponse(deps.db, {
        challengeId: params[0]!,
        response: requireBigInt(b, "response"),
      });
    },
  },
  {
    method: "POST",
    pattern: /^\/api\/verify$/,
    handler: (deps, body) => {
      const b = asObject(body);
      return verifyImportedTranscript(deps.db, {
        transcript: b.transcript,
        expectedContext: typeof b.expectedContext === "string" ? b.expectedContext : undefined,
      });
    },
  },
  {
    method: "GET",
    pattern: /^\/api\/transcripts$/,
    handler: (deps, _b, _p, query) => ({
      transcripts: getTranscripts(deps.db, clampLimit(query.searchParams.get("limit"))),
    }),
  },
  {
    method: "GET",
    pattern: /^\/api\/verifications$/,
    handler: (deps, _b, _p, query) => ({
      verifications: getVerifications(deps.db, clampLimit(query.searchParams.get("limit"))),
    }),
  },
  {
    method: "GET",
    pattern: /^\/api\/export$/,
    handler: (deps) => getPublicData(deps.db),
  },
];

export function createApiServer(deps: ApiDeps): Server {
  return createServer(async (req, res) => {
    await handleRequest(deps, req, res);
  });
}

async function handleRequest(deps: ApiDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/" ) {
    json(res, 200, {
      service: "schnorr-proof-lab",
      warning: "教学实现，禁止用于生产身份认证",
      endpoints: [
        "GET /api/groups",
        "GET /api/groups/:id/check",
        "POST /api/challenges",
        "POST /api/challenges/:id/submit",
        "POST /api/verify",
        "GET /api/transcripts",
        "GET /api/verifications",
        "GET /api/export",
      ],
    });
    return;
  }
  const route = routes.find((r) => r.method === req.method && r.pattern.test(url.pathname));
  if (!route) {
    json(res, 404, { error: "未找到接口", path: url.pathname });
    return;
  }
  try {
    let body: unknown = null;
    if (req.method === "POST") body = await readJsonBody(req);
    const match = url.pathname.match(route.pattern);
    const result = await route.handler(deps, body, match ? match.slice(1) : [], url);
    json(res, 200, result);
  } catch (err) {
    if (err instanceof ValidationError) {
      json(res, 400, { error: err.message });
    } else if (err instanceof NotFoundError) {
      json(res, 404, { error: err.message });
    } else {
      json(res, 500, { error: "服务器内部错误", detail: (err as Error).message });
    }
  }
}

function json(res: ServerResponse, status: number, payload: unknown): void {
  const data = JSON.stringify(payload, null, 2);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(data);
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buf.length;
    if (size > 1_048_576) throw new ValidationError("请求体超过 1MB 限制");
    chunks.push(buf);
  }
  if (chunks.length === 0) throw new ValidationError("POST 请求需要 JSON 体");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ValidationError("JSON 解析失败");
  }
}

function asObject(body: unknown): Record<string, unknown> {
  if (typeof body !== "object" || body === null) throw new ValidationError("请求体必须是对象");
  return body as Record<string, unknown>;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) throw new ValidationError(`字段 ${key} 必须是非空字符串`);
  return v;
}

function requireInt(obj: Record<string, unknown>, key: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isInteger(v)) throw new ValidationError(`字段 ${key} 必须是整数`);
  return v;
}

function requireBigInt(obj: Record<string, unknown>, key: string): bigint {
  const v = obj[key];
  if (typeof v !== "string" || !/^[0-9]+$/.test(v)) {
    throw new ValidationError(`字段 ${key} 必须是十进制整数字符串`);
  }
  return BigInt(v);
}

function clampLimit(raw: string | null): number {
  const n = raw === null ? 100 : Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 100;
  return Math.min(Math.floor(n), 1000);
}

export { transcriptJson, parseTranscriptJson };
