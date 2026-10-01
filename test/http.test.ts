import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApiServer } from "../src/server/http.js";
import { openDatabase } from "../src/server/db.js";
import { GROUP_SMALL } from "../src/crypto/groups.js";
import {
  generateSecretKey,
  publicKeyFromSecret,
  commit,
  buildInteractiveTranscript,
  proveFiatShamir,
} from "../src/crypto/schnorr.js";
import { transcriptJson } from "../src/server/service.js";
import type { Server } from "node:http";

async function withServer(fn: (base: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "schnorr-http-"));
  const db = openDatabase(join(dir, "http.sqlite"));
  const server: Server = createApiServer({ db });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("无端口");
  try {
    await fn(`http://127.0.0.1:${addr.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
  }
}

async function call<T = unknown>(method: string, url: string, body?: unknown): Promise<{ status: number; json: T }> {
  const res = await fetch(url, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: (await res.json()) as T };
}

test("HTTP: 参数检查接口", async () => {
  await withServer(async (base) => {
    const r = await call<{ ok: boolean }>("GET", `${base}/api/groups/small-demo/check`);
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
  });
});

test("HTTP: 交互流程 + 重放拒绝", async () => {
  await withServer(async (base) => {
    const sk = generateSecretKey(GROUP_SMALL);
    const pk = publicKeyFromSecret(GROUP_SMALL, sk);
    const cobj = commit(GROUP_SMALL);
    const issued = await call<{ challengeId: string; challenge: string }>("POST", `${base}/api/challenges`, {
      groupId: GROUP_SMALL.id,
      context: "http-ctx",
      y: pk.y.toString(),
      commitment: cobj.commitment.toString(),
    });
    assert.equal(issued.status, 200);
    const t = buildInteractiveTranscript(GROUP_SMALL, sk, "http-ctx", cobj, BigInt(issued.json.challenge));
    const ok = await call("POST", `${base}/api/challenges/${issued.json.challengeId}/submit`, {
      response: t.response.toString(),
    });
    assert.equal((ok.json as { valid: boolean }).valid, true);
    const replay = await call("POST", `${base}/api/challenges/${issued.json.challengeId}/submit`, {
      response: t.response.toString(),
    });
    assert.equal((replay.json as { valid: boolean }).valid, false);
  });
});

test("HTTP: 并发提交同一挑战仅一次成功", async () => {
  await withServer(async (base) => {
    const sk = generateSecretKey(GROUP_SMALL);
    const pk = publicKeyFromSecret(GROUP_SMALL, sk);
    const cobj = commit(GROUP_SMALL);
    const issued = await call<{ challengeId: string; challenge: string }>("POST", `${base}/api/challenges`, {
      groupId: GROUP_SMALL.id,
      context: "race",
      y: pk.y.toString(),
      commitment: cobj.commitment.toString(),
    });
    const t = buildInteractiveTranscript(GROUP_SMALL, sk, "race", cobj, BigInt(issued.json.challenge));
    const rs = await Promise.all(
      Array.from({ length: 6 }, () =>
        call("POST", `${base}/api/challenges/${issued.json.challengeId}/submit`, {
          response: t.response.toString(),
        }),
      ),
    );
    assert.equal(rs.filter((r) => (r.json as { valid: boolean }).valid).length, 1);
  });
});

test("HTTP: FS 验证与导出", async () => {
  await withServer(async (base) => {
    const sk = generateSecretKey(GROUP_SMALL);
    const proof = proveFiatShamir(GROUP_SMALL, sk, "export-ctx");
    const r = await call<{ valid: boolean }>("POST", `${base}/api/verify`, {
      transcript: transcriptJson(proof),
    });
    assert.equal(r.json.valid, true);
    const exported = await call("GET", `${base}/api/export`);
    const text = JSON.stringify(exported.json);
    assert.doesNotMatch(text, /secretX/);
    assert.doesNotMatch(text, /"nonce"/);
  });
});
