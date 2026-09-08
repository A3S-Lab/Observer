# a3s-observer

<p align="center">
  <strong>Language / 语言:</strong>
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>

面向 AI Agent 的内核级 **eBPF 可观测性——以及可选干预**。它将系统调用与网络事件转化为 Agent 语义遥测（哪个 Agent 运行了哪个工具、发起了哪次 LLM 调用、触碰了哪些文件、到达了哪个端点、是否提权），**零改动 Agent、无需按语言插桩**——同一内核视角还可 **干预**：按外部策略拒绝某 Agent 的出站、文件访问或进程执行。

在 Linux 6.8（Aya）上构建并验证。默认仅观察；每次干预均为显式 opt-in，并与观察路径隔离。

## 架构

**最小核心**——探针 → loader → 身份 → 关联 → 导出——其余皆为可替换 trait。两条路径共享同一内核视角：**观察**始终开启且被动（tracepoint 无法阻断）；**干预**为 opt-in（cgroup-BPF / fanotify），因此策略失误永远无法破坏可观测性。

AnySentry 仅观察模式下 Agent 发现过滤器所用的附加进程/工作负载事实，见 [`docs/agent-discovery-filter.md`](docs/agent-discovery-filter.md)。

```
  AI agent + its tool subprocesses                  unmodified · any language
            │
            │   execve · do_exit · connect · TLS ClientHello · DNS · openat · setuid/ptrace/bind · SSL_*
  ══════════╪═══════════════════════════════════════════════  KERNEL  (eBPF + fanotify)
            ▼
   OBSERVE  (passive, always-on)            INTERVENE  (opt-in, external policy)
     exec  exit  connect  sni  dns           enforce   → cgroup/connect4: deny egress
     security  llm-metrics  file*  ssl*      fileguard → fanotify: deny open + exec
            │
            │  ring buffers
  ══════════╪═══════════════════════════════════════════════  USERSPACE
            ▼
   a3s-observer-collector  (Aya loader)
     identity (k8s pod / proc / comm)  ·  correlate (pid,fd)→peer  ·  export NDJSON
            │
            ▼
   OTel Collector  →  your backend            * opt-in: A3S_OBSERVER_FILES / _SSL
```

## 观察 — who / what / where

一条事件回答 **who**（进程或 k8s pod）/ **what**（工具、文件、LLM 提供商 + 字节 / 延迟 / TTFT，或明文）/ **where**（对端 IP / 主机名）。

| 信号 | 内核钩子 | 事件 |
|---|---|---|
| `exec` | `sys_enter_execve` + `sched_process_exec` | `ToolExec` — 有界 argv 片段、成功 exec 确认、`/proc` 补充 + cwd、comm、uid |
| `exit` | `do_exit` kprobe | `ProcessExit` — 结果：**退出码 + 信号**（正常 / SIGSEGV 崩溃 / SIGKILL-OOM），每进程一条 |
| `connect` | `sys_enter_connect` | `Egress` — 对端 IP:port |
| `sni` | TLS ClientHello（明文 `server_name`） | LLM **提供商** + 端点 |
| `dns` | 发往 :53 的 `sendto` / `sendmsg` / `sendmmsg` | `Dns` — 解析主机名 |
| llm metrics | 每套接字 `read`/`recv` + `close` | `LlmCall` — 请求/响应线字节、延迟、TTFT |
| `file`\* | `sys_enter_openat`（写打开） | `FileAccess` — 写入的文件（`A3S_OBSERVER_FILES=1`） |
| `unlink`\* | `sys_enter_unlink` + `sys_enter_unlinkat` | `FileDelete` — 删除的文件（`A3S_OBSERVER_FILES=1`） |
| `ssl`\* | OpenSSL `SSL_write` / `SSL_read` uprobe | `SslContent` — 请求/响应明文（`A3S_OBSERVER_SSL=1`） |
| `llm-api`\* | 从 `SslContent` 解析 | `LlmApi` — **模型** + token 用量（`A3S_OBSERVER_SSL=1`） |
| `security` | `setuid` / `ptrace` / `bind` 系统调用 | `SecurityAction` — 提权（→root）/ 进程注入 / 打开监听端口（稀少 + 内核内过滤） |
| collector heartbeat | 用户态定时器 | `CollectorHeartbeat` — collector id、node/pod、已附着探针、功能开关、窗口计数、ring 丢弃、输出丢弃 |

用户态为每条事件补充 **身份**（k8s cgroup→pod、`/proc` comm+ppid，或短生命周期进程的内核内 `comm` 回退）、`(pid,fd)→peer` **关联**，以及 **提供商** 分类（SNI → 15 个 LLM 提供商）；然后导出 **NDJSON**（或人类可读日志）。`CollectorHeartbeat` 是面向 AnySentry 等平台的控制面事件；它不是 Agent 动作，不应进入安全策略决策。

**示例输出**（`A3S_OBSERVER_JSON=1`，每行一条事件——此处为可读性换行）：

```json
{"identity":{"agent":"python3","task":"1841","session":null},"provider":"Anthropic",
 "event":{"LlmCall":{"pid":1841,"sni":"api.anthropic.com","peer":"160.79.104.10",
 "req_bytes":284,"resp_bytes":3832,"latency":{"secs":1,"nanos":210000000},
 "ttft":{"secs":0,"nanos":410000000}}}}
{"identity":{"agent":"python3","task":"1903","session":null},"provider":null,
 "event":{"ToolExec":{"pid":1903,"ppid":1841,
 "argv":["git","clone","https://github.com/acme/repo"],"argv_truncated":false,
 "argv_incomplete":false,"exec_confirmed":true,"argv_source":"kernel_fragments",
 "captured_argc":3,"captured_bytes":36,"observed_argc":3,"observed_bytes":36,
 "cwd":"/home/agent/work"}}}
{"identity":{"agent":"python3","task":"1841","session":null},"provider":null,
 "event":{"SslContent":{"pid":1841,"is_read":false,
 "content":"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n..."}}}
```

`ToolExec.argv` 由 collector 从有界 128 字节内核记录重组。collector 最多捕获 12 个参数、约 8 KiB argv。`argv_truncated=true` 表示达到配置上限；`argv_incomplete=true` 表示丢失分块或重组超时。`sched_process_exec` 确认成功 exec 后，collector 会尝试用 `/proc/<pid>/cmdline`（上限 2 MiB）替换截断/不完整片段。`argv_source` 说明哪一路胜出，`exec_confirmed` 区分已提交 exec 与失败尝试。极短生命周期进程可能在读取 `/proc` 前退出，因此显式截断/不完整标志仍是权威证据质量信号。两种情况都不会静默，且计数器会进入 collector heartbeat。

用 `jq` 过滤，例如每条 LLM 调用及其提供商：
`… | jq -c 'select(.event.LlmCall) | {agent:.identity.agent, provider, sni:.event.LlmCall.sni}'`。

在 DaemonSet 中设置 `A3S_OBSERVER_COLLECTOR_ID` 与 `A3S_NODE_NAME`，以便下游舰队健康视图获得稳定 collector 身份。未设置时回退到 pod/主机名。

### 工作负载归属与新鲜度契约

`EnrichedEvent` 还可携带提供商中立的 `workload` 与 `observation` 对象，用于每副本信号：

```json
{
  "workload": {
    "workload_id": "workload-01HV7F5N",
    "deployment_id": "deployment-01HV7F6A",
    "revision_id": "revision-sha256:8f3a",
    "replica_id": "replica-0007",
    "provider_unit_id": "containerd:4f6c2d8a",
    "node_id": "node-us-east-1a-03"
  },
  "observation": {
    "observed_at_unix_nanos": 1720000015000000000,
    "sampled_at_unix_nanos": 1720000014000000000,
    "collection_interval_nanos": 15000000000,
    "freshness": "fresh"
  }
}
```

`WorkloadIdentity` 在构造上必须完整：生产者须提供稳定的 workload、deployment、不可变 revision、逻辑 replica、当前 provider-unit 与 node ID。每个 ID 为不透明平台标识符，限 128 ASCII 字节与标签安全字母表。生产者必须规范化提供商 ID，且不得把租户密钥、显示名或原始用户标签复制进这些字段。逻辑 `replica_id` 在进程重启、收养与重新调度后仍存活；`provider_unit_id` 在运行时单元被替换时变化。

`ObservationMetadata` 报告观察时间、可选采集间隔，以及 `fresh`、`stale`、`unavailable` 或 `unknown` 之一。新鲜与过期数据包含实际采样时间戳。不可用与未知观察省略它，从而给出显式缺数状态，而非零用量哨兵。

这是传输契约，并非声称每副本资源采集已完成。现有 `IdentityResolver` 实现默认不返回工作负载身份；节点级 collector 有意不对每条事件套用同一静态环境身份。多副本 Linux 采集、CPU/内存/网络/进程/重启/可用性采样、重启/收养夹具，以及等价 OTLP 与 Prometheus 指标导出仍为后续工作。

## 干预 — 出站 / 文件 / 执行（opt-in）

同一视角执行 **外部策略**——任意控制器可写的普通文件；内核按动作向 guard 询问 allow/deny。仅观察核心不受影响。两个 guard 均可 **热重载**，并经 **KVM 验证**（拒绝动作返回 `EPERM`）：

| guard | 机制 | 拒绝 |
|---|---|---|
| `a3s-observer-enforce` | eBPF `cgroup/connect4` | 对策略 IP/主机的 `connect()` — cgroup 作用域、fail-open、DNS 再解析 |
| `a3s-observer-fileguard` | fanotify `FAN_OPEN_PERM` + `FAN_OPEN_EXEC_PERM` | 对策略列出文件的 `open()` **与** `exec` |

### 自带策略

决策逻辑 **属于你**，可用任意语言。a3s-observer 提供信号（事件）与执行原语（读取 deny 文件的 guard）；中间策略由你编写：

```
events (NDJSON) → your controller (your rules) → deny-file → guard → kernel denies (EPERM)
```

**出站允许列表** — Agent 只能到达已批准的 LLM 提供商；其余切断：

```bash
# 1. observe  →  2. your controller writes the deny-list  →  3. enforce on the agent's cgroup
A3S_OBSERVER_JSON=1 sudo -E a3s-observer-collector \
  | ./scripts/example-controller.py egress-deny.txt &
sudo a3s-observer-enforce /sys/fs/cgroup/<agent> egress-deny.txt
```

控制器约 10 行——`if` 是你拥有的部分（`scripts/example-controller.py`）：

```python
ALLOWED = {"Anthropic", "OpenAi", "Gemini"}          # your rule
for line in sys.stdin:                               # the NDJSON event stream
    ev = json.loads(line); call = ev.get("event", {}).get("Egress")
    if call and call.get("sni") and ev.get("provider") not in ALLOWED:
        denied.add(call["peer"])                     # → write egress-deny.txt (hot-reloaded)
        open(sys.argv[1], "w").write("\n".join(sorted(denied)) + "\n")
```

**文件 / 执行拒绝** — 无需事件流，只需路径列表（同样热重载）：

```bash
printf '%s\n' /etc/shadow /usr/bin/curl > deny.txt   # deny open(/etc/shadow) + exec(curl)
sudo a3s-observer-fileguard deny.txt                 # edit deny.txt → applies within ~2s
```

Deny 文件格式：**egress** = 每行一个 IPv4 或主机名（主机名在每次重载时 DNS 再解析）；**file/exec** = 每行一个路径。偏好进程内（Rust）嵌入？实现 `Policy` trait（`egress` / `file_write` / `exec` → `Verdict`）。完整设计与双路径见 [`docs/enforcement.md`](docs/enforcement.md)。

**内置 `ProviderPolicy`** — 随附的 `Policy`，按 LLM 提供商允许出站（由默认 `SniClassifier` 从 SNI 分类，或通过 `.with_classifier(classifier, allowed)` 使用任意 `ServiceClassifier`），并 **拒绝提供商不在列表上的任何连接**——`connect4`/cgroup guard 在内核内执行拒绝。这是 observer 侧「让 Agent 留在已批准模型上，远离未批准 API 中继 / 供应链」。**仅出站**——文件/执行保持 fail-open。它是 [a3s-sentry](https://github.com/A3S-Lab/Sentry) *反应式* 按目的地拒绝的主动互补（一开始就只有已批准提供商可达），且 **可在宿主构建**——不增加 eBPF，核心不受影响：

```rust
use a3s_observer::{Provider, ProviderPolicy};

// Default: only a *known, non-approved* provider is denied; unknown destinations
// (package mirrors, telemetry, your own APIs) still pass — deny_unclassified is false.
let policy = ProviderPolicy::new([Provider::Anthropic, Provider::OpenAi]);
// api.anthropic.com → Allow · api.deepseek.com → Deny (known provider, not approved) · github.com → Allow

// Strict "approved providers only" cage: anything that isn't allow-listed — incl. unknown hosts — is denied.
let cage = ProviderPolicy::new([Provider::Anthropic]).deny_unclassified(true);
// api.anthropic.com → Allow · github.com → Deny · no-SNI → Deny
```

## 为何 eBPF，以及边界

- **零插桩、语言无关** — 观察或守护任意 Agent（Python/Node/Go/Rust）而无需改其代码，包括其工具子进程。
- **始终开启核心仅用内核钩子，无 uprobe** — 因此核心 **不提供 LLM prompt/completion 内容**。该内容通过 **opt-in** OpenSSL uprobe 扩展（`A3S_OBSERVER_SSL=1`）可用——仅 OpenSSL（Python/Node/curl …，不含 Go `crypto/tls`），因 uprobe 绑定库符号而留在通用核心之外。（ECH 最终会隐藏 SNI → 回退到 IP/DNS。）
- **a3s-box** — box 是独立客户机内核，因此宿主侧 eBPF 可见 box **出站**（经宿主网络路径），但不可见客户机内 exec/file——那些需要客户机内 collector（第二阶段）。

## 构建与运行

eBPF 需要 nightly + `rust-src` + [`bpf-linker`](https://github.com/aya-rs/bpf-linker)（借用 rustc 捆绑的 LLVM——无需系统 LLVM）：

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo build --release -p a3s-observer-collector    # build.rs compiles + links the eBPF

sudo ./target/release/a3s-observer-collector                          # human-readable log
A3S_OBSERVER_JSON=1 sudo -E ./target/release/a3s-observer-collector   # NDJSON
```

仅 Linux；需要 root（CAP_BPF + CAP_PERFMON）。环境开关：`A3S_OBSERVER_JSON`（NDJSON）、`A3S_OBSERVER_FILES`（遗留合并 FileAccess/FileDelete 开关）、`A3S_OBSERVER_FILE_ACCESS` / `A3S_OBSERVER_FILE_DELETE`（独立覆盖）、`A3S_OBSERVER_SSL`（OpenSSL 内容）、`A3S_OBSERVER_HEARTBEAT`（存活文件路径），以及 `A3S_OBSERVER_JSON_QUEUE_CAPACITY`（有界 NDJSON 突发队列，默认 32768；4096–262144）。

每个 ring 由事件驱动读取器排空到物理独立的 Critical、Semantic 与 Bulk inbox；原始探针证据仅映射到 Critical 或 Semantic。读取器复制固定 POD，从不执行 `/proc`、工作负载解析、分类或 JSON 工作。有界事件时间协调器与单写者处理器在 ring 准入后执行这些操作。用 `A3S_OBSERVER_CRITICAL_INBOX_CAPACITY`（默认 16384）、`A3S_OBSERVER_SEMANTIC_INBOX_CAPACITY`（32768）与 `A3S_OBSERVER_BULK_INBOX_CAPACITY`（4096）配置 inbox。`A3S_OBSERVER_REORDER_CAPACITY`（65536）与 `A3S_OBSERVER_REORDER_WINDOW_NS`（2000000）约束跨 ring 重排。

NDJSON 经 1 MiB 用户态缓冲，最多按 256 行或五毫秒成批写入。其三条优先队列使用 `A3S_OBSERVER_JSON_CRITICAL_QUEUE_CAPACITY`（默认 8192）、`A3S_OBSERVER_JSON_SEMANTIC_QUEUE_CAPACITY`（默认同遗留队列设置）与 `A3S_OBSERVER_JSON_BULK_QUEUE_CAPACITY`（8192）。终端 heartbeat 仅在此前已准入优先车道事件全部刷出后确认。FileAccess 有独立 1 MiB ring；FileDelete 使用单独 4 MiB ring，因为包/容器清理可在毫秒内 unlink 数千文件。内核 ring、Collector inbox、语义输出与写者队列损失保持独立计数器，从不呈现为过滤。

高容量文件捕获可通过设置 `ANYSENTRY_FILTER_RULES_FILE` 消费热重载、节点本地的 cgroup 决策快照。无此变量时保留历史全捕获行为。配置后，权威 Infrastructure 决策可在 ring 前过滤，而 map 未命中、过期/冲突规则、候选丢弃与 `sample` 决策默认保留。仅权威 `drop` 可抑制 FileDelete。快照替换为 epoch 原子：

统一 S5 捕获路径通过 `ANYSENTRY_CAPTURE_PROFILE_MODE=shadow|enforce` opt-in，并使用同一 `ANYSENTRY_FILTER_RULES_FILE`。`shadow` 保持全部十个探针为 FULL，同时报告期望决策。`enforce` 在载荷构造与 ring 预留前应用有界 SAMPLE/AGGREGATE 决策；在当前 Collector 实例持久写入预览 ACK 并验证 generation 围栏激活授权之前，DROP 保持禁用。ACK 默认为 `${ANYSENTRY_FILTER_RULES_FILE}.ack.json`，可用 `ANYSENTRY_FILTER_RULES_ACK_FILE` 覆盖。缺失、过期、冲突、过大、畸形、未确认或过期状态保持 discovery-safe。`legacy` 为默认并保留原始 v1 File 过滤器。S5 与 v1 File 决策互斥。

精确累计 SAMPLE/AGGREGATE/DROP 摘要作为 `CaptureAggregate` Bulk 事件发出。内核账本有意限制为 4096 键；饱和永不恢复无界原始流，而是切换到共享紧急采样预算，并设置 `captureProfile.aggregateLedgerDegraded` 与每探针 `aggregateError`。决策计数器用 `decision_op`；ring 投递计数器用 `physical_record`，不得相加用于 Exec。

```json
{
  "schemaVersion": "anysentry.filter_rule_snapshot.v1",
  "epoch": 42,
  "entries": [
    {
      "cgroupId": "18412",
      "action": "keep",
      "authority": "authoritative",
      "epoch": 42,
      "expiresAt": "2026-08-17T09:00:15Z"
    }
  ]
}
```

`A3S_OBSERVER_FILE_UNKNOWN_POLICY=keep` 为默认，保证未解析 FileAccess 不被预算抑制。仅在需兼容较早有界发现模式时显式设为 `sample`。可选控制为 `A3S_OBSERVER_FILE_UNKNOWN_PER_CGROUP`（默认每窗口 20）、`A3S_OBSERVER_FILE_UNKNOWN_PER_NODE`（默认 1000，按 CPU 分摊）与 `A3S_OBSERVER_FILE_SAMPLE_WINDOW_MS`（默认 1000）。候选 `drop` 条目会安全降级为配置的 Unknown 策略；畸形、混合 epoch 或非单调快照保留上一有效 epoch。

Opt-in 强制执行——针对 Agent 的 cgroup 和/或 deny 列表文件运行：

```bash
sudo ./target/release/a3s-observer-enforce   /sys/fs/cgroup/<agent>  egress-deny.txt
sudo ./target/release/a3s-observer-fileguard  file-exec-deny.txt
```

## 部署

a3s-observer 发出 NDJSON；投递（批处理 / 重试 / 路由到后端）是 OpenTelemetry Collector 的职责，因此进程内 OTLP **有意不**构建：

```
a3s-observer  →  NDJSON  →  OTel Collector (filelog → OTLP)  →  your backend
```

- Collector 配置：[`deploy/otel-collector.yaml`](deploy/otel-collector.yaml)（`memory_limiter` + 可重试发送队列）。每条事件一行合法 JSON——也可落入 vector / Loki / `jq`。
- **Kubernetes：** CI 发布 `ghcr.io/a3s-lab/observer:<tag>`（Trivy 扫描、cosign 签名，含 SBOM + SLSA 溯源）；部署 [`deploy/daemonset.yaml`](deploy/daemonset.yaml)（NDJSON 到 stdout，pod 身份来自 `/proc/<pid>/cgroup`——无 k8s API/RBAC；存活探针，`system-node-critical`）。对无法到达 ghcr.io 的节点，将镜像镜像到集群本地仓库。

## 工作区

| crate | 角色 |
|---|---|
| `a3s-observer` | 契约 + 数据模型（`IdentityResolver` / `ServiceClassifier` / `Exporter` / `Policy`）——可在宿主构建 |
| `a3s-observer-common` | 与 eBPF 探针共享的 `no_std` 类型 |
| `a3s-observer-ebpf` | 探针 + `connect4` 出站 guard，编译为 BPF 字节码 |
| `a3s-observer-collector` | loader、关联、导出；外加 `enforce` 与 `fileguard` 二进制 |

Rust + [Aya](https://aya-rs.dev)。在 Linux 6.8 上验证。

## 已测试

在持续负载下浸泡测试——在真实宿主上观察（含 **跨 8 节点 Kubernetes 集群的 24 分钟大规模浸泡**，仅观察 DaemonSet：RSS 平稳、零丢弃、零重启、无干扰），在隔离 VM 中干预：

| 路径 | 用例（全部无泄漏 + 负载下正确） |
|---|---|
| **observe** | 稳态 20 分钟 · 边界输入 · **真实 a3s-code Agent** · 吞吐 110k 事件/60s · 内存受限（256 Mi）· 重启 ×8 · 空闲 + heartbeat · SIGTERM · 并发 collector · 背压 · 连接抖动 · **8 节点集群** |
| **intervene** | 出站 · 文件/执行 · SSL 内容 guard——以及三者与 collector 并行运行 |

每个新信号均经实况验证（载荷正确、验证器干净加载），并在发布前经对抗式多智能体审查——曾 **两次** 捕获单线程测试遗漏的每线程事件重复（多线程 `do_exit` / `setuid`）。浸泡还暴露两个稳健性缺陷（已修复）：NDJSON stdout 污染（v0.9.1）与输出背压事件循环卡住（v0.9.2）。库行覆盖率 **79.6%**（`cargo llvm-cov`）——不可信 SNI / DNS / cgroup 解析器与完整 15 提供商分类器均有单元测试。

## 安全

特权组件——披露策略与如何验证发布镜像签名（cosign / Sigstore）见 [SECURITY.md](SECURITY.md)。

## 许可证

MIT
