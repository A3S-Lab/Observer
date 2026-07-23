# Observer main 与 UOS Linux 4.19 legacy 集成设计

## 目标

将 Observer `origin/main @ 6a6ef5eeee4f7c6ede0f9e2216adbc94c9e8db9e` 的最新采集能力合入 UOS legacy 部署线，同时保持双杨客户目标内核可加载。

本轮集成分支：

```text
integration/uos20-arm64-0.2.0
```

稳定分支：

```text
build/uos20-arm64-legacy
```

只有通过构建验证和 UOS 目标机验证的集成提交才能合回稳定分支。

## 必须保留的上游能力

- exec argv；
- workload observation contract；
- process/workload attribution；
- 最新公共事件类型；
- 最新 collector 健康与丢弃计数；
- Observer main 的测试。

## 必须保留的 UOS 能力

- `legacy-kernel-4-19` feature；
- `perf-kprobe-legacy` backend；
- BPF ISA v1；
- 无 BTF；
- `kern_version=0x0004135a`；
- ARM64 `pt_regs` syscall 参数读取；
- exec、exit、connect、setuid、ptrace、bind、openat、unlinkat 八个 probe；
- per-CPU scratch maps；
- 无有效 probe 时拒绝健康；
- raw BPF syscall 诊断程序。

## 合并规则

执行 `origin/main` merge 后，不允许整体选择旧版或新版 `a3s-observer-collector/src/main.rs`。应以最新 main collector 为主体，将 legacy backend 作为 feature-gated runtime 接入。

legacy BPF 事件结构与最新 common/userspace 事件结构必须逐字段核对。exec argv 和 workload identity 无法直接由旧内核 probe 提供的字段，应在用户态可靠补全；不能可靠补全的能力必须在健康状态和部署文档中标记为降级。

## 构建和目标机门禁

- collector 为 AArch64；
- 最高 GLIBC 不超过 2.28；
- ELF LOAD 对齐支持 65536 页；
- BPF object 为 EM_BPF；
- 不含 `.BTF` 和 `.BTF.ext`；
- BPF version section 为 `0x0004135a`；
- 只使用目标 Linux 4.19 verifier 接受的 BPF ISA；
- 目标机成功附加八个 probe；
- exec argv、process、file、network 和 heartbeat 事件进入 AnySentry；
- `outputDropped=0`、`errorCount=0`；
- 无 probe 或 ABI 不匹配时服务失败，不报告假健康。

## 发布

目标机验证通过后，将 integration 分支 merge 回：

```text
build/uos20-arm64-legacy
```

并创建与 AnySentry UOS 发布版本对应的 tag。Collector、BPF object、源码 commit、构建工具和目标 ABI 写入发布 `PROVENANCE`。
