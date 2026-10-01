import { loadConfig } from "./config.js";
import { openDatabase } from "./server/db.js";
import { createApiServer } from "./server/http.js";

const config = loadConfig();
const db = openDatabase(config.dbFile);
const server = createApiServer({ db });

server.listen(config.port, config.host, () => {
  console.log("Schnorr 知识证明实验服务已启动（仅教学用途，禁止用于生产身份认证）");
  console.log(`监听地址: http://${config.host}:${config.port}`);
  console.log(`数据目录: ${config.dataDir}`);
  console.log(`数据库:   ${config.dbFile}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    console.log(`\n收到 ${signal}，正在关闭...`);
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
