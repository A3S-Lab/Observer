# AnySentry 容器 BPF 能力诊断包设计

## 目标

为 UOS 20、AArch64、Linux 4.19 容器目标机提供一个可离线上传的诊断包，明确区分：

- 容器缺少 capability、seccomp/LSM/lockdown 拒绝；
- 运行内核未注册 KProbe BPF 程序类型；
- Linux 4.19 `kern_version` 与 `uname -r` 推导值不一致；
- 基础 BPF syscall 可用，但 AnySentry collector 字节码仍不兼容；
- glibc、架构、页大小、tracefs/bpffs、资源限制等部署前置条件不满足。

诊断包不依赖网络，不安装软件，不修改目标机配置。

## 交付物

目录 `anysentry-bpf-container-diagnostics-uos20-arm64/` 包含：

1. `RUN_PASSIVE_CHECK.sh`：纯被动 Bash 检查脚本。
2. `a3s-bpf-syscall-probe`：AArch64、glibc 2.28、64 KiB 页兼容的专用探测器。
3. `RUN_DIAGNOSTICS.sh`：先运行被动检查，再运行 syscall 探测器，将结果写入同一报告。
4. `README.md`：目标机执行方式、结果解释和安全边界。
5. `PROVENANCE` 与 `SHA256SUMS`：构建来源和完整性校验。

用户既可只运行完全被动的 `RUN_PASSIVE_CHECK.sh`，也可运行推荐的
`RUN_DIAGNOSTICS.sh` 获取完整诊断。

## 被动检查范围

`RUN_PASSIVE_CHECK.sh` 只读取系统状态，采集：

- OS、架构、glibc、内核 release/version、页大小；
- 容器/虚拟化类型、PID/用户/mount/cgroup/network namespace inode；
- UID/GID、`CapInh/CapPrm/CapEff/CapBnd/CapAmb`、NoNewPrivileges、seccomp；
- 对 `CAP_SYS_ADMIN`、`CAP_SYS_RESOURCE`、`CAP_BPF`、`CAP_PERFMON` 的明确解码；
- SELinux、AppArmor、kernel lockdown、LSM 列表；
- `unprivileged_bpf_disabled`、`perf_event_paranoid`、`kptr_restrict`；
- `RLIMIT_MEMLOCK` 及进程/文件描述符限制；
- 运行内核配置中的 BPF、KProbe、Perf、BTF、seccomp、namespace 选项；
- bpffs、tracefs/debugfs 的存在、文件系统类型、可读写性；
- `/sys/kernel/btf/vmlinux` 和关键 ARM64 KProbe 符号；
- bpftool/strace/capsh 等诊断工具是否存在；
- 指定 collector 的 SHA256、ELF 架构、解释器、GLIBC 需求、版本输出。

脚本不输出 IP、MAC、路由、DNS、hostname、完整 `/proc/cmdline`、原始 cgroup
路径或环境变量。只从 cmdline 提取与 lockdown/LSM/audit 相关的布尔配置。

## BPF syscall 探测器

探测器使用 Linux 4.19 兼容的原始 `bpf(2)` 属性布局，不依赖 bpftool、libbpf
或目标机编译工具。每个成功创建的 FD 都立即关闭，不 pin、不 attach、不写入
bpffs/tracefs。

测试顺序：

1. `BPF_MAP_CREATE`：ARRAY、PERCPU_ARRAY、PERF_EVENT_ARRAY。
2. 最小 `BPF_PROG_TYPE_SOCKET_FILTER`：验证基本程序加载路径。
3. 最小 `BPF_PROG_TYPE_KPROBE`，使用从 `uname -r` 推导的 `kern_version`。
4. 若 KProbe 返回 `EINVAL`，扫描 `4.19.0` 至 `4.19.255`；首个成功值即报告为
   内核运行时接受的版本编码。
5. 每次 `BPF_PROG_LOAD` 使用 verifier log buffer，并打印 syscall errno、错误文本、
   verifier 日志是否为空。

探测器不调用 `perf_event_open`，因为本阶段只需判断程序能否加载；collector 的
现有失败也发生在 attach 之前。

## 判定矩阵

- Map、Socket Filter、KProbe 都返回 `EPERM`：容器 seccomp/LSM 或 capability
  边界阻止 BPF。
- Map/Socket Filter 成功，KProbe 返回 `EPERM`：缺少 KProbe 所需的
  `CAP_SYS_ADMIN` 或厂商安全策略拒绝 tracing BPF。
- Socket Filter 成功，所有 KProbe 版本均 `EINVAL`：运行内核未注册
  `BPF_PROG_TYPE_KPROBE`，或厂商 BPF ABI 已修改。
- 推导版本 `EINVAL`，扫描到其他 `4.19.x` 成功：`uname -r` 与内核
  `LINUX_VERSION_CODE` 不一致。
- 最小 KProbe 成功、AnySentry collector 失败：容器和 KProbe 基础能力可用，根因
  回到 collector 的指令、helper、map relocation 或 loader 属性。
- verifier 日志非空：以日志中的首个明确错误作为下一轮修复依据。

所有结论都同时输出原始 errno 和证据，不把推断伪装成确定事实。

## 安全和错误处理

- 被动脚本不要求 root，但会注明非 root 导致的不可见项目。
- syscall 探测器建议 root 运行；无权限是有效诊断结果，不作为程序崩溃。
- 所有探测均有明确边界；不挂载、安装、写 sysctl、启停服务、加载模块、pin 或
  attach BPF 程序。
- wrapper 使用 `timeout`，并在报告中记录每个组件的退出码。
- 缺少可选命令时记录 `MISSING`，不中断其余检查。
- 报告默认保存在当前目录，文件名不含 hostname。

## 构建和验证

- 探测器用已缓存的 Zig C 交叉工具链构建到
  `aarch64-linux-gnu.2.28`。
- ELF 必须是 AArch64，最高 GLIBC 不超过 2.28，所有 `PT_LOAD` 对齐不小于
  `0x10000`。
- 探测器提供不执行 syscall 的 `--self-test`，验证版本编码、errno 分类和输出格式。
- 测试先验证脚本纯被动边界，再验证 syscall 探测器测试矩阵和打包校验。
- 最终压缩包内统一为 `root:root`，脚本和二进制 `0755`，文档和校验文件 `0644`。
