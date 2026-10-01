import { resolve } from "node:path";

export interface AppConfig {
  port: number;
  host: string;
  dataDir: string;
  dbFile: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): AppConfig {
  const port = Number(env.PORT ?? 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`非法端口: ${env.PORT}`);
  }
  const dataDir = resolve(cwd, env.DATA_DIR ?? "data");
  return {
    port,
    host: env.HOST ?? "127.0.0.1",
    dataDir,
    dbFile: resolve(dataDir, env.DB_FILE ?? "schnorr-lab.sqlite"),
  };
}
