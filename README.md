# Schnorr 离散对数知识证明实验服务（教学用）

使用 TypeScript + Node.js 内置 `http` + 内置 `node:sqlite` 实现的本地后端，
只提供 **HTTP API 与 CLI**，无前端、无 Docker、无外部在线 API、无付费服务。

> ⚠️ **安全声明**
> 本项目是教学实验代码：小参数离散对数可被穷举，256 位参数位数偏小且未经标准组织审计，
> 代码也没有考虑侧信道、重放网络层防护等工程问题。
> **禁止将本项目或其代码用于真实身份认证、登录或任何生产安全场景。**

## 一、实验内容

证明者向验证者证明“自己知道离散对数 `x`（使 `y = g^x mod p`）”，但不泄露 `x`。

- 公开参数：安全素数 `p`、子群阶 `q`（`q | p-1`）、生成元 `g`
- 密钥：私钥 `x ∈ [1,q-1]`（秘密），公钥 `y = g^x mod p`（公开）
- 交互式三轮：
  - 承诺：`k ← [1,q-1]`，`R = g^k mod p`
  - 挑战：`c ← [1,q-1]`（服务端签发，一次性、带过期时间、绑定上下文/公钥/承诺）
  - 响应：`s = k - c·x (mod q)`
  - 验证：`g^s · y^c ≡ R (mod p)`
- 非交互式（Fiat-Shamir）：
  - `c = H(SHA-256, 规范TLV编码(协议版本, 群ID, p, q, g, y, R, context))`
  - 哈希输入为 **Tag-Length-Value 长度边界编码**，杜绝字符串拼接歧义，
    并通过域分隔标签绑定协议版本、群参数、公钥、承诺与上下文。
- 安全实验：
  - 篡改响应、替换上下文、重复/过期挑战、交互与非交互转录混用均被拒绝；
  - 同一挑战并发提交最多成功一次（SQLite `BEGIN IMMEDIATE` 事务 + 状态约束）；
  - **nonce 重用分析**：同一 `k`、不同 `c` 的两份响应可恢复私钥：
    `x = (s2-s1)·(c1-c2)^{-1} mod q`；不同 nonce 的合法转录不会误报。

## 二、参数集

| ID | 参数 | 用途 |
| --- | --- | --- |
| `small-demo` | `p=23, q=11, g=2` | **明确标注不安全**，可纸笔手算 |
| `fixed-256` | 256 位安全素数（项目内固定常量，`g=2`） | 展示真实数学流程，仍不可用于生产 |

服务启动时检查：`p/q` 素性（Miller-Rabin）、`q | p-1`、`2≤g≤p-2`、
`g^q≡1 mod p`、群元素范围 `[1,p-1]` 与子群成员关系 `v^q≡1`，并拒绝单位元退化公钥/承诺。

可手算样本（`small-demo`，上下文 `lab-context-alpha`）：

```
x=3, k=5, c=7
y = 2^3 mod 23 = 8
R = 2^5 mod 23 = 9
s = (5 - 7·3) mod 11 = 6
验证: 2^6 · 8^7 mod 23 = 18·12 mod 23 = 9 = R ✓
```

## 三、秘密处理原则

- 私钥 `x`、承诺随机数 `k` 只存在于 CLI 本地内存，**从不写入 SQLite、日志或公开导出**；
- 数据库仅保存：群参数、挑战（公开字段 + 状态）、公开转录、验证记录；
- `GET /api/export` 使用字段白名单导出公开数据并附 SHA-256 摘要；
- 随机数使用 `node:crypto` 的系统 CSPRNG + 拒绝采样消除模偏差；
  确定性随机源仅在测试/固定样本中显式注入，默认运行无固定种子。

## 四、环境要求

- Windows 本地环境（也可在其他平台运行）
- Node.js **≥ 22**（开发与验证使用 Node 25，使用内置 `node:sqlite`）
- npm（安装开发期 TypeScript；运行时零第三方依赖）

## 五、构建、测试、启动、演示

```powershell
# 1. 安装开发依赖（typescript / 类型声明）
npm install

# 2. 构建（输出到 dist/）
npm run build

# 3. 运行全部测试（先自动构建，再用 node:test 跑 dist 下测试，共 25 项）
npm test

# 4. 启动 API 服务（默认 127.0.0.1:8787，数据目录 ./data）
npm start

# 5. 端到端教学演示（自动起临时 HTTP 服务，覆盖验证通过/各类篡改/nonce 恢复）
npm run demo
```

可配置项（环境变量）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `8787` | 监听端口 |
| `HOST` | `127.0.0.1` | 监听地址（仅本机） |
| `DATA_DIR` | `./data` | 项目内数据目录 |
| `DB_FILE` | `schnorr-lab.sqlite` | 位于 `DATA_DIR` 下的 SQLite 文件名 |

```powershell
$env:PORT="9000"; $env:DATA_DIR="./data"; npm start
```

## 六、CLI

构建后可用 `node dist/src/cli.js <命令>`：

```powershell
# 参数检查
node dist/src/cli.js check-params --group small-demo
node dist/src/cli.js check-params --group fixed-256

# 本地密钥生成（CSPRNG；--secret 可显式输入，仅用于实验）
node dist/src/cli.js keygen --group small-demo
node dist/src/cli.js keygen --group small-demo --secret 3

# 交互式完整流程（本地走同一套服务代码，演示一次性消费与重放拒绝）
node dist/src/cli.js demo-interactive --group small-demo --secret 3

# Fiat-Shamir 非交互证明并导出公开转录
node dist/src/cli.js demo-fs --group small-demo --secret 3 --context lab-context-alpha --out data/proof.json

# 离线验证（--persist 同时写入本地验证记录）
node dist/src/cli.js verify --file data/proof.json
node dist/src/cli.js verify --file data/proof.json --context lab-context-alpha

# nonce 重用分析：恢复私钥 / 不同 nonce 不误报
node dist/src/cli.js analyze-reuse --file-a data/reuse-a.json --file-b data/reuse-b.json --group small-demo

# 全部内置样本（正确证明/篡改响应/替换上下文/重复挑战/nonce 重用）
node dist/src/cli.js samples
```

`reuse-a.json` / `reuse-b.json` 手算内容（`R=9, y=8`）：

```json
{ "challenge": "7", "response": "6" }
{ "challenge": "4", "response": "4" }
```

恢复：`x=(4-6)·(7-4)^{-1} mod 11 = (-2)·4 mod 11 = 3`。

## 七、HTTP API

仅监听本机，JSON 收发，大整数使用十进制字符串。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查 |
| GET | `/api/groups` | 公开群参数列表 |
| GET | `/api/groups/:id/check` | 参数检查（素性/子群阶/生成元） |
| POST | `/api/challenges` | 签发一次性挑战（body: `groupId,context,y,commitment,ttlMs?`） |
| POST | `/api/challenges/:id/submit` | 提交交互响应（body: `response`），消费一次 |
| POST | `/api/verify` | 离线/导入验证转录（`transcript,expectedContext?`） |
| GET | `/api/transcripts?limit=` | 公开转录列表 |
| GET | `/api/verifications?limit=` | 验证记录列表 |
| GET | `/api/export` | 导出全部公开数据（白名单 + 摘要） |

PowerShell 调用示例：

```powershell
$body = @{ groupId="small-demo"; context="lab-context-alpha"; y="8"; commitment="9"; ttlMs=60000 } | ConvertTo-Json
$ch = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/challenges -ContentType "application/json" -Body $body
# s=6 对应 x=3,k=5,c 为服务端返回值时才成立；实际实验请用 CLI 计算响应
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8787/api/challenges/$($ch.challengeId)/submit" -ContentType "application/json" -Body (@{response="6"} | ConvertTo-Json)
```

转录 JSON 结构（交互与非交互用 `kind` 区分，禁止混用）：

```json
{
  "kind": "interactive | noninteractive-fiat-shamir",
  "protocolVersion": "schnorr-zkp-v1",
  "groupId": "small-demo",
  "context": "lab-context-alpha",
  "y": "8",
  "commitment": "9",
  "challenge": "7",
  "response": "6"
}
```

## 八、测试覆盖

- 真实验证方程（小参数手算值、256 位参数流程）
- 边界值：`x=0/q`、`c=0`、`s=q`、元素越界、非子群元素、单位元
- 编码歧义：`["ab","c"]` vs `["a","bc"]`、域标签、类型标签
- Fiat-Shamir 篡改承诺/公钥/上下文
- 跨上下文复用、过期挑战、重复消费、**并发一次性消费**
- 服务重启后消费状态持久化（重新打开同一 SQLite 文件）
- 交互/非交互类型混用、非法转录 JSON
- nonce 重用恢复成功且不同 nonce 不误报
- 公开导出不含 `x/nonce/secretX`

## 九、目录结构

```
src/
  crypto/      BigInt 模运算、TLV 编码、群参数检查、Schnorr/FS、nonce 分析
  server/      SQLite 持久化、服务层、HTTP API
  samples.ts   固定手算样本
  cli.ts       命令行入口
  server.ts    API 服务入口
scripts/demo.ts  端到端演示
test/            node:test 测试
data/            运行时生成（已在 .gitignore 中忽略）
```

## 十、已知限制

- 非恒定时间实现，可能存在计时侧信道；
- 无网络层认证/限流/传输加密，仅绑定本机地址；
- `node:sqlite` 在当前 Node 版本带实验性警告（API 稳定前可能变化）；
- 仅用于理解零知识知识证明协议与常见攻击，不构成任何安全产品。
