#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline)) inline

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

enum {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_LRU_HASH = 9,
};

struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

#if defined(A3S_BPF_ARCH_X86_64)
/* x86-64 user-mode pt_regs field order (only the leading fields we touch). */
struct pt_regs {
    u64 r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si, di, orig_ax;
    u64 ip, cs, flags, sp, ss;
};
#else
struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};
#endif

#define ARGV_SLOTS 12
#define ARG_LEN 128
#define PATH_SNAP_LEN 256
#define FILE_DELETE_FLAG 0xffffffffU
#define SEC_SETUID 1
#define SEC_PTRACE 2
#define SEC_BIND 3
#define BPF_F_CURRENT_CPU 0xffffffffULL
#define UOS_KERNEL_VERSION_4_19_90 0x0004135aU

/* Userspace ABI mirror of CaptureDecisionContext (a3s-observer-common). The legacy backend
 * has no capture-profile engine, so events carry a zeroed decision. */
struct capture_decision {
    u64 capture_epoch;
    u8 capture_profile;
    u8 capture_action;
    u8 capture_authority;
    u8 capture_disposition;
    u8 flags;
    u8 _reserved[3];
};

struct exec_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 argc;
    u8 comm[16];
    u8 filename[128];
    u8 args[ARGV_SLOTS][ARG_LEN];
};

/* These four layouts must match a3s-observer-common byte for byte: the legacy collector
 * deserializes perf records as the common structs and silently drops short records. */
struct exit_event {
    u64 cgroup_id;
    u32 pid;
    u32 exit_code;
    u32 signal;
    u8 comm[16];
    u32 _pad;
    u64 exec_id;
    u64 captured_at_boot_ns;
    struct capture_decision decision;
};

struct connect_event {
    u64 cgroup_id;
    u32 pid;
    u32 fd;
    u16 family;
    u16 port;
    u8 addr[16];
    u8 comm[16];
    u8 _event_time_pad[4];
    u64 captured_at_boot_ns;
    struct capture_decision decision;
};

struct file_event {
    u64 cgroup_id;
    u32 pid;
    u32 flags;
    u8 comm[16];
    u8 path[PATH_SNAP_LEN];
    u64 captured_at_boot_ns;
    struct capture_decision decision;
};

struct sec_event {
    u64 cgroup_id;
    u32 pid;
    u32 kind;
    u64 detail;
    u8 comm[16];
    u64 captured_at_boot_ns;
    struct capture_decision decision;
};

#define LEGACY_PLAINTEXT_LEN (16 * 1024)
#define LEGACY_PLAINTEXT_DIRECTION_WRITE 0
#define LEGACY_PLAINTEXT_DIRECTION_READ 1

/* Fixed-size HTTP payload slice from a socket syscall, emitted only for PIDs admitted through
 * the identity whitelist (PLAINTEXT_ALLOWED). Mirrors LegacyPlaintextEvent in
 * a3s-observer-common; userspace reassembles chunks into HTTP interactions. */
struct plaintext_event {
    u32 pid;
    u32 fd;
    u32 direction;
    u32 len;
    u32 orig_len;
    u32 _pad;
    /* 每次连接生成本地递增的代际号：connect/accept 成功、close 时 +1。fd 号复用
     * （旧连接关闭后新连接拿到同号 fd）不再与旧泳道混淆；userspace 把它混入
     * connection_id，并按 (pid, fd, gen) 重置 chunk 序号。0 = 采集器启动前已存在。 */
    u32 fd_generation;
    u8 comm[16];
    u64 captured_at_boot_ns;
    u8 data[LEGACY_PLAINTEXT_LEN];
};

/* Enter/exit correlation for read/recvfrom: the response buffer is only known at enter time,
 * the bytes are only readable at exit time. Keyed by the full pid_tgid. */
struct read_args {
    u64 buf;
    u64 fd;
};

_Static_assert(sizeof(struct capture_decision) == 16, "capture_decision ABI mismatch");
_Static_assert(sizeof(struct exec_event) == 1696, "exec_event ABI mismatch");
_Static_assert(sizeof(struct exit_event) == 72, "exit_event ABI mismatch");
_Static_assert(sizeof(struct connect_event) == 80, "connect_event ABI mismatch");
_Static_assert(sizeof(struct file_event) == 312, "file_event ABI mismatch");
_Static_assert(sizeof(struct sec_event) == 64, "sec_event ABI mismatch");
_Static_assert(sizeof(struct plaintext_event) == 16440, "plaintext_event ABI mismatch");

/* uprobe（OpenSSL libssl SSL_read/SSL_write）用户态 TLS 明文分块。连接身份用 SSL* 指针
 * （tls_ctx），天然免疫 fd 号复用；与 plaintext_event 分离是为了不动 syscall 通道的
 * ABI（仿真环境 arm64 冻结面只增不改）。 */
struct plaintext_tls_event {
    u32 pid;
    u32 direction;
    u32 len;
    u32 orig_len;
    u64 tls_ctx;
    u8 comm[16];
    u64 captured_at_boot_ns;
    u8 data[LEGACY_PLAINTEXT_LEN];
};
_Static_assert(sizeof(struct plaintext_tls_event) == 16432, "plaintext_tls_event ABI mismatch");

/* SSL_read 进入/返回关联：进入时只有 buf 指针，返回时才知道读到的长度。按 pid_tgid 键。 */
struct ssl_read_args {
    u64 ssl;
    u64 buf;
    u64 count_ptr;   /* SSL_read_ex 的 size_t *readbytes（老 SSL_read 为 0） */
};
_Static_assert(sizeof(struct read_args) == 16, "read_args ABI mismatch");

#define PERF_MAP(name) \
    struct bpf_map_def SEC("maps") name = { \
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, .key_size = 4, .value_size = 4 \
    }
#define SCRATCH_MAP(name, event_type) \
    struct bpf_map_def SEC("maps") name = { \
        .type = BPF_MAP_TYPE_PERCPU_ARRAY, .key_size = 4, \
        .value_size = sizeof(event_type), .max_entries = 1 \
    }

PERF_MAP(EVENTS);
PERF_MAP(EXIT_EVENTS);
PERF_MAP(CONNECT_EVENTS);
PERF_MAP(FILE_EVENTS);
PERF_MAP(SEC_EVENTS);
PERF_MAP(PLAINTEXT_EVENTS);
PERF_MAP(PLAINTEXT_TLS_EVENTS);
SCRATCH_MAP(EXEC_SCRATCH, struct exec_event);
SCRATCH_MAP(EXIT_SCRATCH, struct exit_event);
SCRATCH_MAP(CONNECT_SCRATCH, struct connect_event);
SCRATCH_MAP(FILE_SCRATCH, struct file_event);
SCRATCH_MAP(SEC_SCRATCH, struct sec_event);
SCRATCH_MAP(PLAINTEXT_SCRATCH, struct plaintext_event);
SCRATCH_MAP(PLAINTEXT_TLS_SCRATCH, struct plaintext_tls_event);
SCRATCH_MAP(DROPS, u64);

/* Identity-whitelisted TGIDs admitted to plaintext payload capture. Written by the userspace
 * collector from the forwarder's tls-agent-cgroups document; deleted on process exit. */
struct bpf_map_def SEC("maps") PLAINTEXT_ALLOWED = {
    .type = BPF_MAP_TYPE_HASH, .key_size = 4, .value_size = 1, .max_entries = 65536
};
struct bpf_map_def SEC("maps") PLAINTEXT_READ_ARGS = {
    .type = BPF_MAP_TYPE_HASH, .key_size = 8, .value_size = sizeof(struct read_args),
    .max_entries = 16384
};
/* (pid<<32|fd) -> 连接代际。LRU 自动淘汰：白名单进程高频 close 不会撑满表；
 * 淘汰后代际回到 1，只有"旧泳道仍存活且 fd+gen 完全重合"才会串道，概率极低。 */
struct bpf_map_def SEC("maps") PLAINTEXT_FD_GEN = {
    .type = BPF_MAP_TYPE_LRU_HASH, .key_size = 8, .value_size = 4,
    .max_entries = 16384
};
struct bpf_map_def SEC("maps") SSL_READ_ARGS = {
    .type = BPF_MAP_TYPE_HASH, .key_size = 8, .value_size = sizeof(struct ssl_read_args),
    .max_entries = 16384
};

/* UOS reports 4.19.0 in uname but its BPF KProbe gate requires 4.19.90. */
#ifndef A3S_BPF_KERN_VERSION
#define A3S_BPF_KERN_VERSION UOS_KERNEL_VERSION_4_19_90
#endif
u32 A3S_KERNEL_VERSION SEC("version") = A3S_BPF_KERN_VERSION;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
#ifndef A3S_BPF_KERNEL_READ_HELPER
/* ARM64 4.19 legacy kernels have helper 4 and it reads kernel memory fine.
 * 开发机 Rocky 9.6 (5.14.0-570.el9) 实测相反：helper 117 (probe_read_kernel) 读
 * syscall 包装入口的 pt_regs 必返 -EINVAL，helper 4 读内核态正常——x86_64 通道
 * 构建必须传 -DA3S_BPF_KERNEL_READ_HELPER=4。 */
#define A3S_BPF_KERNEL_READ_HELPER 4
#endif
static long (*bpf_probe_read)(void *dst, u32 size, const void *src) = (void *)A3S_BPF_KERNEL_READ_HELPER;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static long (*bpf_perf_event_output)(void *ctx, void *map, u64 flags,
                                     const void *data, u64 size) = (void *)25;
/* UOS 4.19.90（Kunpeng 920，CONFIG_ARM64_PAN=y）实测：helper 4/45 读用户态内存必返
 * -EFAULT（现场 chunk 日志 read_rc=14，argv/path 全空）。该机 BPF 回移植（0x4135a）
 * 带 5.5+ 的 probe_read_user[_str]（bpf-inspect helpers 试加载 112/114 通过验证器），
 * 走 uaccess/LDTR 路径天然绕过 PAN。所有"读用户态"的调用点必须换成它们；
 * 读内核态（如 syscall_arg 解引用的 pt_regs）保持 helper 4。 */
static long (*bpf_probe_read_user)(void *dst, u32 size, const void *src) = (void *)112;
static long (*bpf_probe_read_user_str)(void *dst, u32 size, const void *src) = (void *)114;
#if defined(A3S_BPF_DIAG)
static long (*bpf_trace_printk)(const char *fmt, u32 fmt_size, ...) = (void *)6;
static long (*bpf_probe_read_compat)(void *dst, u32 size, const void *src) = (void *)4;
#endif

INLINE void count_drop(void) {
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&DROPS, &key);
    if (value)
        *value += 1;
}

INLINE void *scratch(void *map) {
    u32 key = 0;
    return bpf_map_lookup_elem(map, &key);
}

INLINE u64 syscall_arg(struct pt_regs *ctx, u32 index) {
#if defined(A3S_BPF_ARCH_X86_64)
    /* __x64_sys_*(const struct pt_regs *u)：kprobe ctx->di 是 u 指针；系统调用参数在
       u->di/si/dx/r10/r8/r9（内核态读走 bpf_probe_read，x86 实测须 helper 4，构建侧指定）。 */
    struct pt_regs *uregs = (struct pt_regs *)ctx->di;
    u64 value = 0;
    if (!uregs || index > 5)
        return 0;
    switch (index) {
    case 0: bpf_probe_read(&value, sizeof(value), &uregs->di); break;
    case 1: bpf_probe_read(&value, sizeof(value), &uregs->si); break;
    case 2: bpf_probe_read(&value, sizeof(value), &uregs->dx); break;
    case 3: bpf_probe_read(&value, sizeof(value), &uregs->r10); break;
    case 4: bpf_probe_read(&value, sizeof(value), &uregs->r8); break;
    default: bpf_probe_read(&value, sizeof(value), &uregs->r9); break;
    }
    return value;
#else
    struct pt_regs *syscall_regs = (struct pt_regs *)ctx->regs[0];
    u64 value = 0;
    if (syscall_regs)
        bpf_probe_read(&value, sizeof(value), &syscall_regs->regs[index]);
    return value;
#endif
}

INLINE void output(void *ctx, void *map, const void *event, u64 size) {
    if (bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, event, size) < 0)
        count_drop();
}

/* The legacy backend has no capture-profile engine and no reliable cgroup id on hybrid
 * layouts: userspace resolves identity from /proc instead. Fill the additive ABI fields with
 * explicit zeroes plus the monotonic capture time so short/garbage tails can never leak. */
INLINE void event_common_init(u64 *cgroup_id, u64 *captured_at_boot_ns,
                              struct capture_decision *decision) {
    *cgroup_id = 0;
    *captured_at_boot_ns = bpf_ktime_get_ns();
    __builtin_memset(decision, 0, sizeof(*decision));
}

#define READ_EXEC_ARG(index) \
    arg = 0; \
    if (bpf_probe_read_user(&arg, sizeof(arg), (const void *)(argv + ((index) * 8))) < 0 || arg == 0) \
        goto submit_exec; \
    event->args[(index)][0] = 0; \
    bpf_probe_read_user_str(event->args[(index)], ARG_LEN, (const void *)arg); \
    event->argc = (index) + 1

INLINE int plaintext_admitted(u32 pid) {
    return bpf_map_lookup_elem(&PLAINTEXT_ALLOWED, &pid) != 0;
}

#if !defined(A3S_BPF_DST_NARROW)
INLINE u32 fd_gen_current(u32 pid, u32 fd) {
    const u64 key = ((u64)pid << 32) | fd;
    const u32 *gen = bpf_map_lookup_elem(&PLAINTEXT_FD_GEN, &key);
    return gen ? *gen : 0;
}

INLINE void fd_gen_bump(u32 pid, u32 fd) {
    const u64 key = ((u64)pid << 32) | fd;
    const u32 *cur = bpf_map_lookup_elem(&PLAINTEXT_FD_GEN, &key);
    const u32 next = cur ? *cur + 1 : 1;
    bpf_map_update_elem(&PLAINTEXT_FD_GEN, &key, &next, 0);
}
#endif

/* 前 4 字节按小端比较 HTTP/1.x 请求方法或响应行。文件日志、Redis RESP、TLS 握手、
 * 二进制协议（PK/ thrift 等）一律不匹配——用于存量连接的收养判定。 */
#if defined(A3S_BPF_DST_NARROW)
/* 开发机定向收窄（铁律：仅 x86 开发通道构建启用，仿真环境 arm64 打包绝不含）：
 * 只跟踪到 LLM 网关 122.144.165.65:18890 的明文连接。 */
#define FD_GEN_ALLOW 0x80000000U
#define FD_GEN_MASK 0x7fffffffU
INLINE int dst_narrow_allow(u32 ip_be, u16 port) {
    return port == 18890 && ip_be == 0x7a90a541U;
}
/* accept/close：换代际并清除允许位——入站 fd 与关闭后的复用 fd 都不采。 */
INLINE void fd_gen_rotate_blocked(u32 pid, u32 fd) {
    const u64 key = ((u64)pid << 32) | fd;
    const u32 *cur = bpf_map_lookup_elem(&PLAINTEXT_FD_GEN, &key);
    const u32 next = cur ? ((*cur & FD_GEN_MASK) + 1) : 1;
    bpf_map_update_elem(&PLAINTEXT_FD_GEN, &key, &next, 0);
}
#endif

#if !defined(A3S_BPF_DST_NARROW)
INLINE int is_http1_prefix32(u32 w) {
    return w == 0x20544547U /* "GET " */ || w == 0x54534f50U /* "POST" */ ||
           w == 0x20545550U /* "PUT " */ || w == 0x44414548U /* "HEAD" */ ||
           w == 0x50545448U /* "HTTP" */ || w == 0x4954504fU /* "OPTI" */ ||
           w == 0x43544150U /* "PATC" */ || w == 0x454c4544U /* "DELE" */ ||
           w == 0x43415254U /* "TRAC" */ || w == 0x4e4e4f43U /* "CONN" */;
}
#endif

SEC("kprobe")
int legacy_exec(struct pt_regs *ctx) {
    const u64 filename = syscall_arg(ctx, 0);
    const u64 argv = syscall_arg(ctx, 1);
    struct exec_event *event;
    u64 arg;

    if (!filename)
        return 0;
    event = scratch(&EXEC_SCRATCH);
    if (!event) {
        count_drop();
        return 0;
    }
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->ppid = 0;
    event->uid = (u32)bpf_get_current_uid_gid();
    event->argc = 0;
    event->filename[0] = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const void *)filename);
    if (!argv)
        goto submit_exec;
    READ_EXEC_ARG(0);
    READ_EXEC_ARG(1);
    READ_EXEC_ARG(2);
    READ_EXEC_ARG(3);
    READ_EXEC_ARG(4);
    READ_EXEC_ARG(5);
    READ_EXEC_ARG(6);
    READ_EXEC_ARG(7);
    READ_EXEC_ARG(8);
    READ_EXEC_ARG(9);
    READ_EXEC_ARG(10);
    READ_EXEC_ARG(11);

submit_exec:
    output(ctx, &EVENTS, event, sizeof(*event));
    return 0;
}

SEC("kprobe")
int legacy_exit(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
#if defined(A3S_BPF_ARCH_X86_64)
    const u64 code = ctx->di;   /* do_exit(long code)：普通内核函数，arg0 在 di */
#else
    const u64 code = ctx->regs[0];
#endif
    struct exit_event *event;
    /* Per-thread read-arg correlation is keyed by the full pid_tgid; drop it for any exiting
     * thread. The pid admission entry is shared by the whole thread group, so only the group
     * leader's exit revokes it. */
    bpf_map_delete_elem(&PLAINTEXT_READ_ARGS, &id);
    if ((u32)(id >> 32) == (u32)id) {
        const u32 tgid = (u32)(id >> 32);
        bpf_map_delete_elem(&PLAINTEXT_ALLOWED, &tgid);
    } else {
        return 0;
    }
    event = scratch(&EXIT_SCRATCH);
    if (!event) {
        count_drop();
        return 0;
    }
    event_common_init(&event->cgroup_id, &event->captured_at_boot_ns, &event->decision);
    event->pid = (u32)(id >> 32);
    event->exit_code = (u32)((code >> 8) & 0xff);
    event->signal = (u32)(code & 0x7f);
    event->exec_id = 0;
    event->_pad = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    output(ctx, &EXIT_EVENTS, event, sizeof(*event));
    return 0;
}

SEC("kprobe")
int legacy_connect(struct pt_regs *ctx) {
    const u64 fd = syscall_arg(ctx, 0);
    const u64 sockaddr = syscall_arg(ctx, 1);
    const u64 addrlen = syscall_arg(ctx, 2);
    struct connect_event *event;
    u16 family = 0;
    u16 network_port = 0;
    if (!sockaddr || addrlen < 8)
        return 0;
    if (bpf_probe_read_user(&family, sizeof(family), (const void *)sockaddr) < 0)
        return 0;
    if (family != 2 && family != 10)
        return 0;
    {
        const u32 connect_pid = (u32)(bpf_get_current_pid_tgid() >> 32);
        if (plaintext_admitted(connect_pid)) {
#if defined(A3S_BPF_DST_NARROW)
            u16 dport = 0;
            u32 dip = 0;
            bpf_probe_read_user(&dport, sizeof(dport), (const void *)(sockaddr + 2));
            if (family == 2)
                bpf_probe_read_user(&dip, sizeof(dip), (const void *)(sockaddr + 4));
            const u64 key = ((u64)connect_pid << 32) | (u32)fd;
            const u32 *cur = bpf_map_lookup_elem(&PLAINTEXT_FD_GEN, &key);
            u32 next = cur ? ((*cur & FD_GEN_MASK) + 1) : 1;
            if (dst_narrow_allow(__builtin_bswap32(dip), __builtin_bswap16(dport)))
                next |= FD_GEN_ALLOW;
            bpf_map_update_elem(&PLAINTEXT_FD_GEN, &key, &next, 0);
#else
            fd_gen_bump(connect_pid, (u32)fd);
#endif
        }
    }
    event = scratch(&CONNECT_SCRATCH);
    if (!event) {
        count_drop();
        return 0;
    }
    event_common_init(&event->cgroup_id, &event->captured_at_boot_ns, &event->decision);
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->fd = (u32)fd;
    event->family = family;
    bpf_probe_read_user(&network_port, sizeof(network_port), (const void *)(sockaddr + 2));
    event->port = __builtin_bswap16(network_port);
    event->addr[0] = 0; event->addr[1] = 0; event->addr[2] = 0; event->addr[3] = 0;
    event->addr[4] = 0; event->addr[5] = 0; event->addr[6] = 0; event->addr[7] = 0;
    event->addr[8] = 0; event->addr[9] = 0; event->addr[10] = 0; event->addr[11] = 0;
    event->addr[12] = 0; event->addr[13] = 0; event->addr[14] = 0; event->addr[15] = 0;
    if (family == 2)
        bpf_probe_read_user(event->addr, 4, (const void *)(sockaddr + 4));
    else
        bpf_probe_read_user(event->addr, 16, (const void *)(sockaddr + 8));
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    output(ctx, &CONNECT_EVENTS, event, sizeof(*event));
    return 0;
}

INLINE void emit_file(struct pt_regs *ctx, u64 path, u32 flags) {
    struct file_event *event;
    if (!path)
        return;
    event = scratch(&FILE_SCRATCH);
    if (!event) {
        count_drop();
        return;
    }
    event_common_init(&event->cgroup_id, &event->captured_at_boot_ns, &event->decision);
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->flags = flags;
    event->path[0] = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(event->path, sizeof(event->path), (const void *)path);
    output(ctx, &FILE_EVENTS, event, sizeof(*event));
}

SEC("kprobe")
int legacy_openat(struct pt_regs *ctx) {
    const u32 flags = (u32)syscall_arg(ctx, 2);
    if ((flags & 3) != 0)
        emit_file(ctx, syscall_arg(ctx, 1), flags);
    return 0;
}

SEC("kprobe")
int legacy_unlinkat(struct pt_regs *ctx) {
    emit_file(ctx, syscall_arg(ctx, 1), FILE_DELETE_FLAG);
    return 0;
}

INLINE void emit_security(struct pt_regs *ctx, u32 kind, u64 detail) {
    struct sec_event *event = scratch(&SEC_SCRATCH);
    if (!event) {
        count_drop();
        return;
    }
    event_common_init(&event->cgroup_id, &event->captured_at_boot_ns, &event->decision);
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->kind = kind;
    event->detail = detail;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    output(ctx, &SEC_EVENTS, event, sizeof(*event));
}

SEC("kprobe")
int legacy_setuid(struct pt_regs *ctx) {
    const u32 target = (u32)syscall_arg(ctx, 0);
    if (target == 0 && (u32)bpf_get_current_uid_gid() != 0)
        emit_security(ctx, SEC_SETUID, 0);
    return 0;
}

SEC("kprobe")
int legacy_ptrace(struct pt_regs *ctx) {
    const u64 request = syscall_arg(ctx, 0);
    if (request == 16 || request == 0x4206)
        emit_security(ctx, SEC_PTRACE, syscall_arg(ctx, 1));
    return 0;
}

SEC("kprobe")
int legacy_bind(struct pt_regs *ctx) {
    const u64 sockaddr = syscall_arg(ctx, 1);
    u16 network_port = 0;
    u16 port;
    if (!sockaddr)
        return 0;
    if (bpf_probe_read_user(&network_port, sizeof(network_port), (const void *)(sockaddr + 2)) < 0)
        return 0;
    port = __builtin_bswap16(network_port);
    if (port)
        emit_security(ctx, SEC_BIND, port);
    return 0;
}


/* Copy one bounded payload slice and emit only its valid header+payload prefix. The payload
 * read uses a constant size because the 4.19 verifier does not propagate range narrowing across
 * register copies (observed on UOS 4.19.90, compat19 field). event->len stays the authoritative
 * valid-byte count for userspace; the perf record is trimmed to len so short socket calls do not
 * consume a 16 KiB ring slot. If the full window crosses an unmapped page, retry with a small
 * fixed window before dropping the payload. */
INLINE void emit_plaintext(struct pt_regs *ctx, u32 pid, u32 fd, u64 buf, u64 count,
                           u32 direction) {
    struct plaintext_event *event;
    u32 len;
    if (!buf || !count)
        return;
    event = scratch(&PLAINTEXT_SCRATCH);
    if (!event) {
        count_drop();
        return;
    }
    len = (u32)count;
    if (len > LEGACY_PLAINTEXT_LEN)
        len = LEGACY_PLAINTEXT_LEN;
    event->pid = pid;
    event->fd = fd;
    event->direction = direction;
    event->orig_len = count > 0xffffffffULL ? 0xffffffffU : (u32)count;
    event->len = len;
    event->_pad = 0;
    /* 采集器启动前已存在的连接（gen==0）：只在嗅到 HTTP 前缀时收养进跟踪，
     * 否则丢弃——白名单进程的文件/管道/Redis 字节不再占用 perf 通道。 */
#if defined(A3S_BPF_DST_NARROW)
    /* 收窄构建：只有目的地命中的连接（bit31）才采，代际另行可取。 */
    {
        const u64 key = ((u64)pid << 32) | fd;
        const u32 *val = bpf_map_lookup_elem(&PLAINTEXT_FD_GEN, &key);
        if (!val || !(*val & FD_GEN_ALLOW))
            return;
        event->fd_generation = *val & FD_GEN_MASK;
    }
#else
    u32 gen = fd_gen_current(pid, fd);
    if (gen == 0) {
        u32 prefix = 0;
        if (bpf_probe_read_user(&prefix, sizeof(prefix), (const void *)buf) < 0 ||
            !is_http1_prefix32(prefix))
            return;
        fd_gen_bump(pid, fd);
        gen = fd_gen_current(pid, fd);
    }
    event->fd_generation = gen;
#endif
    event->captured_at_boot_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->data[0] = 0;
    /* UOS 4.19.90 现场：helper 112 的变量长度读会被 verifier 判为 unbounded，
     * 因此按固定窗口顺序复制 1 KiB + 1/3 KiB + 三个 4 KiB 块，覆盖 16 KiB 上限。
     * 每个窗口失败时保留已验证前缀，不再为读不到的未来字节伪造完整载荷。 */
    {
        const long rc1 = bpf_probe_read_user(event->data, 1024, (const void *)buf);
        if (rc1 < 0) {
            const long rc2 = bpf_probe_read_user(event->data, 64, (const void *)buf);
            event->_pad = ((u32)(-rc1) & 0xffffu) | (((u32)(-rc2) & 0xffffu) << 16);
            if (rc2 < 0)
                event->len = 0;
            else if (event->len > 64)
                event->len = 64;
        } else {
            event->_pad = 0;
            if (len > 1024) {
                long rc2;
                if (len <= 2048)
                    rc2 = bpf_probe_read_user(event->data + 1024, 1024,
                                              (const void *)(buf + 1024));
                else
                    rc2 = bpf_probe_read_user(event->data + 1024, 3072,
                                              (const void *)(buf + 1024));
                if (rc2 < 0) {
                    event->_pad = (((u32)(-rc1) & 0xffffu) << 16) | ((u32)(-rc2) & 0xffffu);
                    event->len = 1024;
                } else if (len > 4096) {
                    const long rc3 = bpf_probe_read_user(event->data + 4096, 4096,
                                                         (const void *)(buf + 4096));
                    if (rc3 < 0) {
                        event->_pad = (((u32)(-rc1) & 0xffffu) << 16) | ((u32)(-rc3) & 0xffffu);
                        event->len = 4096;
                    } else if (len > 8192) {
                        const long rc4 = bpf_probe_read_user(event->data + 8192, 4096,
                                                             (const void *)(buf + 8192));
                        if (rc4 < 0) {
                            event->_pad = (((u32)(-rc1) & 0xffffu) << 16) | ((u32)(-rc4) & 0xffffu);
                            event->len = 8192;
                        } else if (len > 12288) {
                            const long rc5 = bpf_probe_read_user(event->data + 12288, 4096,
                                                                 (const void *)(buf + 12288));
                            if (rc5 < 0) {
                                event->_pad = (((u32)(-rc1) & 0xffffu) << 16) | ((u32)(-rc5) & 0xffffu);
                                event->len = 12288;
                            }
                        }
                    }
                }
            }
        }
    }
    {
        /* Values reloaded from a map are unbounded to the verifier (modern kernels
         * reject an unbounded bpf_perf_event_output size). Re-clamp into a local so
         * the emitted record size is provably within the event allocation; on 4.19
         * this is idempotent with the clamp already applied to len above. */
        u32 emit_len = event->len;
        if (emit_len > LEGACY_PLAINTEXT_LEN)
            emit_len = LEGACY_PLAINTEXT_LEN;
        output(ctx, &PLAINTEXT_EVENTS, event,
               sizeof(*event) - LEGACY_PLAINTEXT_LEN + emit_len);
    }
}

INLINE void plaintext_write(struct pt_regs *ctx) {
    const u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    if (!plaintext_admitted(pid))
        return;
    emit_plaintext(ctx, pid, (u32)syscall_arg(ctx, 0), syscall_arg(ctx, 1),
                   syscall_arg(ctx, 2), LEGACY_PLAINTEXT_DIRECTION_WRITE);
}

INLINE void plaintext_read_enter(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    struct read_args args;
    if (!plaintext_admitted((u32)(id >> 32)))
        return;
    args.buf = syscall_arg(ctx, 1);
    args.fd = syscall_arg(ctx, 0);
    bpf_map_update_elem(&PLAINTEXT_READ_ARGS, &id, &args, 0);
}

INLINE void plaintext_read_exit(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    struct read_args *args = bpf_map_lookup_elem(&PLAINTEXT_READ_ARGS, &id);
    u64 buf;
    u64 fd;
#if defined(A3S_BPF_ARCH_X86_64)
    const long retval = (long)ctx->ax;   /* kretprobe：函数返回值在 rax */
#else
    const long retval = (long)ctx->regs[0];
#endif
    if (!args)
        return;
    buf = args->buf;
    fd = args->fd;
    bpf_map_delete_elem(&PLAINTEXT_READ_ARGS, &id);
    if (retval <= 0)
        return;
    emit_plaintext(ctx, (u32)(id >> 32), (u32)fd, buf, (u64)retval,
                   LEGACY_PLAINTEXT_DIRECTION_READ);
}

SEC("kprobe")
int legacy_http_write(struct pt_regs *ctx) {
    plaintext_write(ctx);
    return 0;
}

SEC("kprobe")
int legacy_http_sendto(struct pt_regs *ctx) {
    plaintext_write(ctx);
    return 0;
}

SEC("kprobe")
int legacy_http_read_enter(struct pt_regs *ctx) {
    plaintext_read_enter(ctx);
    return 0;
}

SEC("kprobe")
int legacy_http_recvfrom_enter(struct pt_regs *ctx) {
    plaintext_read_enter(ctx);
    return 0;
}

SEC("kretprobe")
int legacy_http_read_exit(struct pt_regs *ctx) {
    plaintext_read_exit(ctx);
    return 0;
}

SEC("kretprobe")
int legacy_http_recvfrom_exit(struct pt_regs *ctx) {
    plaintext_read_exit(ctx);
    return 0;
}

/* 服务端侧：accept/accept4 返回的新 fd 换代际（白名单进程的入站连接）。 */
INLINE void accept_gen_bump(struct pt_regs *ctx) {
#if defined(A3S_BPF_DST_NARROW)
    /* 收窄构建：入站 fd 换代且清允许位（防止复用继承旧连接的采集资格） */
    const long newfd_n = (long)ctx->ax;
    const u32 pid_n = (u32)(bpf_get_current_pid_tgid() >> 32);
    if (newfd_n >= 0 && plaintext_admitted(pid_n))
        fd_gen_rotate_blocked(pid_n, (u32)newfd_n);
    return;
#else
#if defined(A3S_BPF_ARCH_X86_64)
    const long newfd = (long)ctx->ax;
#else
    const long newfd = (long)ctx->regs[0];
#endif
    const u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    if (newfd < 0 || !plaintext_admitted(pid))
        return;
    fd_gen_bump(pid, (u32)newfd);
#endif
}

SEC("kretprobe")
int legacy_http_accept_ret(struct pt_regs *ctx) {
    accept_gen_bump(ctx);
    return 0;
}

SEC("kretprobe")
int legacy_http_accept4_ret(struct pt_regs *ctx) {
    accept_gen_bump(ctx);
    return 0;
}

/* close 也换代：socket fd 关闭后同号 fd 可能改作文件/新连接，旧泳道字节就此封口。 */
SEC("kprobe")
int legacy_http_close(struct pt_regs *ctx) {
    const u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    if (!plaintext_admitted(pid))
        return 0;
#if defined(A3S_BPF_DST_NARROW)
    fd_gen_rotate_blocked(pid, (u32)syscall_arg(ctx, 0));
#else
    fd_gen_bump(pid, (u32)syscall_arg(ctx, 0));
#endif
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

/* 与 emit_plaintext 同款的定长窗口复制（4.19 验证器只认常量长度）；差别只在事件类型
 * 与 tls_ctx 身份字段，没有 fd/代际——SSL* 指针即连接身份。 */
INLINE void emit_tls_plaintext(struct pt_regs *ctx, u32 pid, u64 tls_ctx, u64 buf,
                               u64 count, u32 direction) {
    struct plaintext_tls_event *event;
    u32 len;
    if (!buf || !count || !tls_ctx)
        return;
    event = scratch(&PLAINTEXT_TLS_SCRATCH);
    if (!event) {
        count_drop();
        return;
    }
    len = (u32)count;
    if (len > LEGACY_PLAINTEXT_LEN)
        len = LEGACY_PLAINTEXT_LEN;
    event->pid = pid;
    event->direction = direction;
    event->orig_len = count > 0xffffffffULL ? 0xffffffffU : (u32)count;
    event->len = len;
    event->tls_ctx = tls_ctx;
    event->captured_at_boot_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->data[0] = 0;
    {
        const long rc1 = bpf_probe_read_user(event->data, 1024, (const void *)buf);
        if (rc1 < 0) {
            const long rc2 = bpf_probe_read_user(event->data, 64, (const void *)buf);
            if (rc2 < 0)
                event->len = 0;
            else if (event->len > 64)
                event->len = 64;
        } else {
            if (len > 1024) {
                long rc2;
                if (len <= 2048)
                    rc2 = bpf_probe_read_user(event->data + 1024, 1024,
                                              (const void *)(buf + 1024));
                else
                    rc2 = bpf_probe_read_user(event->data + 1024, 3072,
                                              (const void *)(buf + 1024));
                if (rc2 < 0) {
                    event->len = 1024;
                } else if (len > 4096) {
                    const long rc3 = bpf_probe_read_user(event->data + 4096, 4096,
                                                         (const void *)(buf + 4096));
                    if (rc3 < 0) {
                        event->len = 4096;
                    } else if (len > 8192) {
                        const long rc4 = bpf_probe_read_user(event->data + 8192, 4096,
                                                             (const void *)(buf + 8192));
                        if (rc4 < 0) {
                            event->len = 8192;
                        } else if (len > 12288) {
                            const long rc5 = bpf_probe_read_user(event->data + 12288, 4096,
                                                                 (const void *)(buf + 12288));
                            if (rc5 < 0)
                                event->len = 12288;
                        }
                    }
                }
            }
        }
    }
    {
        u32 emit_len = event->len;
        if (emit_len > LEGACY_PLAINTEXT_LEN)
            emit_len = LEGACY_PLAINTEXT_LEN;
        output(ctx, &PLAINTEXT_TLS_EVENTS, event,
               sizeof(*event) - LEGACY_PLAINTEXT_LEN + emit_len);
    }
}

SEC("uprobe")
int legacy_ssl_write(struct pt_regs *ctx) {
    const u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    if (!plaintext_admitted(pid))
        return 0;
#if defined(A3S_BPF_ARCH_X86_64)
    const u64 ssl = ctx->di;
    const u64 buf = ctx->si;
    const u64 num = ctx->dx;
#else
    const u64 ssl = ctx->regs[0];
    const u64 buf = ctx->regs[1];
    const u64 num = ctx->regs[2];
#endif
    emit_tls_plaintext(ctx, pid, ssl, buf, num, LEGACY_PLAINTEXT_DIRECTION_WRITE);
    return 0;
}

/* OpenSSL 1.1.1+ 的 _ex 变体是主流量（CPython 3.12 起只用 _ex）；SSL_write 内部亦是
 * SSL_write_ex 的包装。write_ex 的 num 在 arg2，与 write 同布局，entry 直接采 buf。 */
SEC("uprobe")
int legacy_ssl_write_ex(struct pt_regs *ctx) {
    const u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    if (!plaintext_admitted(pid))
        return 0;
#if defined(A3S_BPF_ARCH_X86_64)
    const u64 ssl = ctx->di;
    const u64 buf = ctx->si;
    const u64 num = ctx->dx;
#else
    const u64 ssl = ctx->regs[0];
    const u64 buf = ctx->regs[1];
    const u64 num = ctx->regs[2];
#endif
    emit_tls_plaintext(ctx, pid, ssl, buf, num, LEGACY_PLAINTEXT_DIRECTION_WRITE);
    return 0;
}

SEC("uprobe")
int legacy_ssl_read_enter(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!plaintext_admitted((u32)(id >> 32)))
        return 0;
    struct ssl_read_args args;
#if defined(A3S_BPF_ARCH_X86_64)
    args.ssl = ctx->di;
    args.buf = ctx->si;
#else
    args.ssl = ctx->regs[0];
    args.buf = ctx->regs[1];
#endif
    args.count_ptr = 0;
    bpf_map_update_elem(&SSL_READ_ARGS, &id, &args, 0);
    return 0;
}

/* SSL_read_ex 入口：多读 arg3（size_t *readbytes）作为返回长度的用户态地址。
 * x86_64 arg3=r9，arm64 arg3=regs[3]。 */
SEC("uprobe")
int legacy_ssl_read_enter_ex(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!plaintext_admitted((u32)(id >> 32)))
        return 0;
    struct ssl_read_args args;
#if defined(A3S_BPF_ARCH_X86_64)
    /* SysV 参数序：rdi, rsi, rdx, rcx, r8, r9 —— arg3 是 rcx（不是 r9）。 */
    args.ssl = ctx->di;
    args.buf = ctx->si;
    args.count_ptr = ctx->cx;
#else
    args.ssl = ctx->regs[0];
    args.buf = ctx->regs[1];
    args.count_ptr = ctx->regs[3];
#endif
    bpf_map_update_elem(&SSL_READ_ARGS, &id, &args, 0);
    return 0;
}

SEC("uretprobe")
int legacy_ssl_read_exit(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&SSL_READ_ARGS, &id);
    u64 ssl;
    u64 buf;
#if defined(A3S_BPF_ARCH_X86_64)
    const long retval = (long)ctx->ax;
#else
    const long retval = (long)ctx->regs[0];
#endif
    if (!args)
        return 0;
    ssl = args->ssl;
    buf = args->buf;
    {
        const u64 count_ptr = args->count_ptr;
        bpf_map_delete_elem(&SSL_READ_ARGS, &id);
        if (retval <= 0)
            return 0;
        u64 nbytes = (u64)retval;
        if (count_ptr) {
            /* SSL_read_ex 返回 1/0，真实字节数在 *readbytes（用户态） */
            nbytes = 0;
            if (bpf_probe_read_user(&nbytes, sizeof(nbytes), (const void *)count_ptr) < 0)
                return 0;
        }
        if (!nbytes)
            return 0;
        emit_tls_plaintext(ctx, (u32)(id >> 32), ssl, buf, nbytes,
                           LEGACY_PLAINTEXT_DIRECTION_READ);
    }
    return 0;
}

#if defined(A3S_BPF_DIAG)
/* 开发机 x86_64 排障专用（A3S_BPF_DIAG 编译门控，默认构建不含，仿真环境冻结对象不含）。
 * 输出在 /sys/kernel/tracing/trace。trace_printk 每次最多 3 个参数。 */
SEC("kprobe")
int legacy_diag_connect(struct pt_regs *ctx) {
    u64 di = 0, fd4 = 0, fd117 = 0;
    long rc4 = -1, rc117 = -1;
#if defined(A3S_BPF_ARCH_X86_64)
    struct pt_regs *uregs = (struct pt_regs *)ctx->di;
    di = (u64)uregs;
    if (uregs) {
        rc117 = bpf_probe_read(&fd117, sizeof(fd117), &uregs->di);
        rc4 = bpf_probe_read_compat(&fd4, sizeof(fd4), &uregs->di);
    }
#endif
    char fmt1[] = "a3sd1 di=%lx rc117=%ld fd117=%lu\n";
    bpf_trace_printk(fmt1, sizeof(fmt1), di, rc117, fd117);
    char fmt2[] = "a3sd2 rc4=%ld fd4=%lu\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), rc4, fd4, 0);
    return 0;
}

SEC("kprobe")
int legacy_diag_sysconnect(struct pt_regs *ctx) {
    u64 fd = 0, sa = 0, alen = 0;
    u16 fam112 = 0, fam4 = 0;
    long rc112 = -1, rc4 = -1;
#if defined(A3S_BPF_ARCH_X86_64)
    fd = ctx->di;
    sa = ctx->si;
    alen = ctx->dx;
#endif
    if (sa) {
        rc112 = bpf_probe_read_user(&fam112, sizeof(fam112), (const void *)sa);
        rc4 = bpf_probe_read_compat(&fam4, sizeof(fam4), (const void *)sa);
    }
    char fmt[] = "a3sd3 fd=%lu sa=%lx alen=%lu\n";
    bpf_trace_printk(fmt, sizeof(fmt), fd, sa, alen);
    char fmtb[] = "a3sd3b fam112=%u rc112=%ld fam4=%u\n";
    bpf_trace_printk(fmtb, sizeof(fmtb), (u64)fam112, rc112, (u64)fam4);
    char fmtc[] = "a3sd3c rc4=%ld\n";
    bpf_trace_printk(fmtc, sizeof(fmtc), (u64)rc4, 0, 0);
    return 0;
}

SEC("kprobe")
int legacy_diag_ksysread(struct pt_regs *ctx) {
    u64 fd = 0, buf = 0, count = 0;
#if defined(A3S_BPF_ARCH_X86_64)
    fd = ctx->di;
    buf = ctx->si;
    count = ctx->dx;
#endif
    if ((int)fd <= 2 || count < 4096)
        return 0;
    char fmt[] = "a3sd4 fd=%lu buf=%lx count=%lu\n";
    bpf_trace_printk(fmt, sizeof(fmt), fd, buf, count);
    return 0;
}

SEC("kretprobe")
int legacy_diag_ksysread_ret(struct pt_regs *ctx) {
    long rv = 0;
#if defined(A3S_BPF_ARCH_X86_64)
    rv = (long)ctx->ax;
#endif
    if (rv < 4096)
        return 0;
    char fmt[] = "a3sd5 rv=%ld\n";
    bpf_trace_printk(fmt, sizeof(fmt), (u64)rv, 0, 0);
    return 0;
}
#endif
