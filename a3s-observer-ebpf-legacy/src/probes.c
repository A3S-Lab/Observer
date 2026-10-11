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
};

struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

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

#define LEGACY_PLAINTEXT_LEN 512
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
_Static_assert(sizeof(struct plaintext_event) == 560, "plaintext_event ABI mismatch");
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
SCRATCH_MAP(EXEC_SCRATCH, struct exec_event);
SCRATCH_MAP(EXIT_SCRATCH, struct exit_event);
SCRATCH_MAP(CONNECT_SCRATCH, struct connect_event);
SCRATCH_MAP(FILE_SCRATCH, struct file_event);
SCRATCH_MAP(SEC_SCRATCH, struct sec_event);
SCRATCH_MAP(PLAINTEXT_SCRATCH, struct plaintext_event);
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

/* UOS reports 4.19.0 in uname but its BPF KProbe gate requires 4.19.90. */
u32 A3S_KERNEL_VERSION SEC("version") = UOS_KERNEL_VERSION_4_19_90;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, u32 size, const void *src) = (void *)4;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static long (*bpf_perf_event_output)(void *ctx, void *map, u64 flags,
                                     const void *data, u64 size) = (void *)25;
static long (*bpf_probe_read_str)(void *dst, u32 size, const void *src) = (void *)45;

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
    struct pt_regs *syscall_regs = (struct pt_regs *)ctx->regs[0];
    u64 value = 0;
    if (syscall_regs)
        bpf_probe_read(&value, sizeof(value), &syscall_regs->regs[index]);
    return value;
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
    if (bpf_probe_read(&arg, sizeof(arg), (const void *)(argv + ((index) * 8))) < 0 || arg == 0) \
        goto submit_exec; \
    event->args[(index)][0] = 0; \
    bpf_probe_read_str(event->args[(index)], ARG_LEN, (const void *)arg); \
    event->argc = (index) + 1

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
    bpf_probe_read_str(event->filename, sizeof(event->filename), (const void *)filename);
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
    const u64 code = ctx->regs[0];
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
    if (bpf_probe_read(&family, sizeof(family), (const void *)sockaddr) < 0)
        return 0;
    if (family != 2 && family != 10)
        return 0;
    event = scratch(&CONNECT_SCRATCH);
    if (!event) {
        count_drop();
        return 0;
    }
    event_common_init(&event->cgroup_id, &event->captured_at_boot_ns, &event->decision);
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->fd = (u32)fd;
    event->family = family;
    bpf_probe_read(&network_port, sizeof(network_port), (const void *)(sockaddr + 2));
    event->port = __builtin_bswap16(network_port);
    event->addr[0] = 0; event->addr[1] = 0; event->addr[2] = 0; event->addr[3] = 0;
    event->addr[4] = 0; event->addr[5] = 0; event->addr[6] = 0; event->addr[7] = 0;
    event->addr[8] = 0; event->addr[9] = 0; event->addr[10] = 0; event->addr[11] = 0;
    event->addr[12] = 0; event->addr[13] = 0; event->addr[14] = 0; event->addr[15] = 0;
    if (family == 2)
        bpf_probe_read(event->addr, 4, (const void *)(sockaddr + 4));
    else
        bpf_probe_read(event->addr, 16, (const void *)(sockaddr + 8));
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
    bpf_probe_read_str(event->path, sizeof(event->path), (const void *)path);
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
    if (bpf_probe_read(&network_port, sizeof(network_port), (const void *)(sockaddr + 2)) < 0)
        return 0;
    port = __builtin_bswap16(network_port);
    if (port)
        emit_security(ctx, SEC_BIND, port);
    return 0;
}

INLINE int plaintext_admitted(u32 pid) {
    return bpf_map_lookup_elem(&PLAINTEXT_ALLOWED, &pid) != 0;
}

/* Copy one bounded payload slice and emit it as a fixed-size record. The variable-length
 * probe_read is clamped before use so the 4.19 verifier can prove the bound; the record itself
 * stays fixed-size so the perf ABI never varies. HTTP syntax is deliberately judged in
 * userspace (the interaction reassembler), keeping the kernel side product-neutral. */
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
    event->captured_at_boot_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->data[0] = 0;
    if (len)
        bpf_probe_read(event->data, len, (const void *)buf);
    output(ctx, &PLAINTEXT_EVENTS, event, sizeof(*event));
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
    const long retval = (long)ctx->regs[0];
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

char LICENSE[] SEC("license") = "GPL";
