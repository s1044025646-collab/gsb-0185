# Schnorr 离散对数知识证明：转录生成与篡改验证（教学实验后端）

仅包含 **API 与 CLI** 的本地实验服务，用于在课堂上演示 **Schnorr 离散对数知识证明**：
公开群参数 `(p, q, g)`、公钥 `y = g^x mod p`、承诺 `t = g^k mod p`、挑战 `c`、响应
`s = k - c·x mod q`，以及验证方程 `g^s · y^c ≡ t (mod p)`。

> **安全警告**
> 本项目是**教学实验**，不是可部署的身份认证系统。`small-unsafe-demo` 是可穷举的极小参数；
> 即使是 512 位大参数，本代码也缺少生产所需的侧信道防护、审计、密钥管理等。
> **禁止将本实现直接用于任何真实身份认证或签名场景。**

## 功能

- TypeScript + Node.js（v22.5+，推荐 v24/v25）+ 内置 `node:sqlite`，**零运行时第三方依赖**，无需 Docker/WSL/网络。
- BigInt 自实现模幂、模逆、承诺/响应计算、Schnorr 验证方程。
- 两组固定参数，均在启动时检查：素性、`q | p−1`、生成元阶恰为 `q`、群元素范围与子群归属。
  - `small-unsafe-demo`：`p=607, q=101, g=7`（**明确标注不安全**，可手算/穷举）。
  - `fixed-large-512`：512 位安全素数 `p=2q+1`，256 位 `q`，`g=3`，仅用于展示数学流程。
- 交互式证明：服务端签发随机挑战，**TTL 过期、一次性消费、上下文绑定**；
  `BEGIN IMMEDIATE` 事务保证**同一挑战并发提交最多一次成功**。
- 非交互式证明：基于 SHA-256 的 Fiat-Shamir 变换。
- **规范编码**：哈希输入使用带 8 字节长度边界的 TLV（Tag-Length-Value），绑定
  协议版本、转录类型、群参数（label/p/q/g）、公钥、承诺、上下文，杜绝字符串拼接歧义
  （`("ab","c")` 与 `("a","bc")` 编码必然不同）。
- 随机数来自 `node:crypto.randomBytes`（系统 CSPRNG），拒绝采样消除模偏差；
  测试可注入确定性随机源，默认运行**不使用固定种子**。
- SQLite 只保存公开数据：参数、待验证挑战、公开转录、验证记录。
  **表结构中没有私钥/nonce 列**；查询、日志、导出均不返回它们。
- nonce 重用分析（仅限小参数）：相同 nonce、不同挑战时
  `x = (s1−s2)·(c2−c1)^-1 mod q` 恢复私钥；承诺不同（合法不同 nonce）不会误报；
  相同挑战（重放）也不构成恢复条件。
- 交互/非交互转录带显式 `version` 与 `transcriptType`，验证时按声明类型检查，禁止混用。
- 样本：可手算正确证明、篡改响应、替换上下文、重复挑战、nonce 重用（见 `samples/`）。

## 快速开始（Windows PowerShell）

```powershell
node --version          # 需要 v22.5.0 或更高（开发机为 v25.5.0）
npm install
npm run build
npm test                # 26 个测试（真实方程/边界值/编码歧义/重启持久/并发/HTTP）
npm run demo            # 端到端教学演示（通过/篡改/重放/过期/并发/恢复秘密）
npm start               # 启动 API，默认 http://localhost:3000
```

启动参数与环境变量：

```powershell
node dist/server.js --port 8080 --data-dir ./data   # 或 $env:PORT=8080; $env:DATA_DIR="./data"
```

## CLI

```powershell
# 参数
node dist/cli.js groups
node dist/cli.js check-params --group small-unsafe-demo

# 本地生成密钥（私钥默认只显示在屏幕；--save-secret 才写文件）
node dist/cli.js keygen --group small-unsafe-demo --out data/key.json
node dist/cli.js keygen --group fixed-large-512 --save-secret data/secret.json

# 用私钥生成 Fiat-Shamir 证明（公开转录入库；--nonce 仅供测试复现）
node dist/cli.js prove --group small-unsafe-demo --secret 7 --context classroom-A --out data/p.json

# 离线验证（兼容信封 JSON 与裸转录）
node dist/cli.js verify --in data/p.json
node dist/cli.js verify --in samples/02-tampered-response.json   # 退出码 2，显示失败原因

# 与运行中的服务完成交互三段流程
node dist/cli.js interactive --group small-unsafe-demo --secret 7 --context demo --url http://localhost:3000

# nonce 重用恢复演示
node dist/cli.js nonce-reuse

# 导入转录验证入库 / 导出全部公开数据 / 列出本地记录
node dist/cli.js import --in samples/01-valid-fiat-shamir.json
node dist/cli.js export --out data/export.json
node dist/cli.js list
```

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/health` | 健康检查（含教学警告） |
| GET  | `/api/groups` | 公开参数集及参数检查结果 |
| GET  | `/api/groups/:label/check` | 单个参数集检查 |
| POST | `/api/commitment` | 实验便利接口：返回承诺与 **仅本次** 的 nonce（服务不保存） |
| POST | `/api/challenges` | 签发交互挑战：`{group,context,publicKey,commitment,ttlMs?}` |
| POST | `/api/challenges/submit` | 提交响应一次性消费：`{challengeId,response,context?}` |
| POST | `/api/proofs/demo` | 教学演示：服务端临时造秘密并回显（不落库、不写日志） |
| POST | `/api/proofs/non-interactive` | 保存 CLI 本地生成的非交互公开转录 |
| POST | `/api/verify` | 离线验证任意转录（返回 422 表示验证失败） |
| POST | `/api/analysis/nonce-reuse` | 小参数 nonce 重用恢复样本 |
| GET  | `/api/challenges` `/api/transcripts` `/api/verifications` | 公开记录查询 |
| GET  | `/api/export` | 导出公开转录与验证记录（无秘密） |

PowerShell 调用示例：

```powershell
$demo = Invoke-RestMethod -Method Post -Uri http://localhost:3000/api/proofs/demo `
  -ContentType "application/json" -Body '{"group":"small-unsafe-demo","context":"d","secretScalar":"7"}'
Invoke-RestMethod -Method Post -Uri http://localhost:3000/api/verify `
  -ContentType "application/json" -Body ($demo.transcript | ConvertTo-Json)
```

## 手算示例（小参数）

`p=607, q=101, g=7`，取私钥 `x=7`、nonce `k=13`、上下文 `classroom-A`：

- 公钥 `y = 7^7 mod 607 = 451`
- 承诺 `t = 7^13 mod 607 = 8`
- Fiat-Shamir 挑战 `c = SHA256(TLV(...)) mod 101`（值见 `samples/01-*.json`）
- 响应 `s = (k − c·x) mod 101`
- 验证 `7^s · 451^c mod 607 == 8`

nonce 重用恢复（`k=13, x=7`，挑战 `c1=5, c2=42`）：

- `s1 = k−5x`, `s2 = k−42x (mod 101)`
- `x = (s1−s2)·(42−5)^-1 mod 101 = 7`

## 数据与隐私

- 数据库文件默认 `data/schnorr.db`（SQLite WAL），仅含公开表：
  `groups_meta`、`challenges`、`transcripts`、`verifications`。
- 私钥与 nonce **不在表结构中**；`/api/export` 与 `cli export` 可直接检查。
- `/api/proofs/demo` 与 `/api/commitment` 会在响应里短暂返回秘密/nonce 以方便课堂演示，
  真实使用请用 CLI 在本地持有私钥，只把公开值提交给服务。
- 服务访问日志只记录方法、路径、状态码，不记录请求体。

## 目录结构

```
src/
  encoding.ts   带长度边界的 TLV 规范编码 + SHA-256
  bignum.ts     模幂/模逆、CSPRNG 采样、可注入随机源
  params.ts     两组固定参数、素性/子群/生成元/元素范围检查
  proof.ts      Schnorr 承诺/挑战/响应/验证、Fiat-Shamir、nonce 重用分析
  db.ts         SQLite 表与原子消费事务（不存秘密）
  service.ts    业务逻辑
  server.ts     零依赖 HTTP API
  cli.ts        命令行
  demo.ts       端到端教学演示
  make-samples.ts 生成 samples/ 样本
  tests/        node:test 测试（26 个）
samples/        正确/篡改/换上下文/重复挑战/nonce 重用样本
```

## 已知限制

- 教学代码：小参数不安全；大参数仅 512 位且无侧信道防护，不可用于生产。
- `node:sqlite` 在部分 Node 版本打印 ExperimentalWarning，不影响功能。
- 交互流程的证明者便利接口 `/api/commitment` 会返回 nonce（实验用途）；生产模型中
  nonce 必须只存在于证明者本地。
