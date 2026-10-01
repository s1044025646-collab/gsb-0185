import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { rmSync } from "node:fs";
function cleanupDir(dir: string) {
  for (let i = 0; i < 10; i++) {
    try { cleanupDir(dir); return; } catch { }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  }
  try { cleanupDir(dir); } catch { }
}
import type { AddressInfo } from "node:net";
import { SchnorrService } from "../service.js";
import { createApp } from "../server.js";
import { SMALL_GROUP } from "../params.js";
import { dec, respond, commit, generateKeyPair } from "../proof.js";

async function startServer(dir: string) {
  const svc = SchnorrService.open(resolve(dir, "schnorr.db"));
  const server = createApp(svc);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;
  async function call(path: string, body?: unknown): Promise<{ status: number; data: any }> {
    const res = await fetch(base + path, {
      method: body ? "POST" : "GET",
      headers: { "content-type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json();
    return { status: res.status, data };
  }
  return { base, call, close: () => { server.close(); svc.close(); } };
}

test("HTTP: health/groups/验证/挑战全链路", async () => {
  const dir = resolve(tmpdir(), `schnorr-http-${Date.now()}`);
  const srv = await startServer(dir);
  try {
    const health = await srv.call("/health");
    assert.equal(health.status, 200);

    const groups = await srv.call("/api/groups");
    assert.equal(groups.data.groups.length, 2);

    const gp = SMALL_GROUP;
    const kp = generateKeyPair(gp);
    const cc = commit(gp);
    const issued = await srv.call("/api/challenges", {
      group: gp.label, context: "http", publicKey: dec(kp.publicKey), commitment: dec(cc.commitment),
    });
    assert.equal(issued.status, 201);
    const s = dec(respond(gp, cc.nonce, BigInt(issued.data.challenge), kp.secretScalar));
    const ok = await srv.call("/api/challenges/submit", { challengeId: issued.data.challengeId, response: s });
    assert.equal(ok.data.valid, true);

    const dup = await srv.call("/api/challenges/submit", { challengeId: issued.data.challengeId, response: s });
    assert.equal(dup.status, 409);

    const exported = await srv.call("/api/export");
    const text = JSON.stringify(exported.data);
    assert.ok(!text.includes("secretScalar"));
    assert.ok(!text.includes('"nonce"'));
  } finally {
    srv.close();
    cleanupDir(dir);
  }
});

test("HTTP: demo 生成的证明可离线验证，篡改响应被拒", async () => {
  const dir = resolve(tmpdir(), `schnorr-http2-${Date.now()}`);
  const srv = await startServer(dir);
  try {
    const demo = await srv.call("/api/proofs/demo", { group: "small-unsafe-demo", context: "d", secretScalar: "7" });
    assert.equal(demo.status, 200);
    const verifyOk = await srv.call("/api/verify", demo.data.transcript);
    assert.equal(verifyOk.data.valid, true);

    const bad = { ...demo.data.transcript, response: String((BigInt(demo.data.transcript.response) + 1n) % SMALL_GROUP.q) };
    const verifyBad = await srv.call("/api/verify", bad);
    assert.equal(verifyBad.status, 422);
    assert.equal(verifyBad.data.valid, false);
  } finally {
    srv.close();
    cleanupDir(dir);
  }
});


