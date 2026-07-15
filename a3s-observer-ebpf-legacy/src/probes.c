#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline)) inline

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

enum {
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

struct exec_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 argc;
    u8 comm[16];
    u8 filename[128];
    u8 args[ARGV_SLOTS][ARG_LEN];
};

struct exit_event {
    u32 pid;
    u32 exit_code;
    u32 signal;
    u8 comm[16];
};

struct connect_event {
    u32 pid;
    u32 fd;
    u16 family;
    u16 port;
    u8 addr[16];
    u8 comm[16];
};

struct file_event {
    u32 pid;
    u32 flags;
    u8 comm[16];
    u8 path[PATH_SNAP_LEN];
};

struct sec_event {
    u32 pid;
    u32 kind;
    u64 detail;
    u8 comm[16];
};

_Static_assert(sizeof(struct exec_event) == 1696, "exec_event ABI mismatch");
_Static_assert(sizeof(struct exit_event) == 28, "exit_event ABI mismatch");
_Static_assert(sizeof(struct connect_event) == 44, "connect_event ABI mismatch");
_Static_assert(sizeof(struct file_event) == 280, "file_event ABI mismatch");
_Static_assert(sizeof(struct sec_event) == 32, "sec_event ABI mismatch");

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
SCRATCH_MAP(EXEC_SCRATCH, struct exec_event);
SCRATCH_MAP(EXIT_SCRATCH, struct exit_event);
SCRATCH_MAP(CONNECT_SCRATCH, struct connect_event);
SCRATCH_MAP(FILE_SCRATCH, struct file_event);
SCRATCH_MAP(SEC_SCRATCH, struct sec_event);
SCRATCH_MAP(DROPS, u64);

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_probe_read)(void *dst, u32 size, const void *src) = (void *)4;
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
    if ((u32)(id >> 32) != (u32)id)
        return 0;
    event = scratch(&EXIT_SCRATCH);
    if (!event) {
        count_drop();
        return 0;
    }
    event->pid = (u32)(id >> 32);
    event->exit_code = (u32)((code >> 8) & 0xff);
    event->signal = (u32)(code & 0x7f);
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

char LICENSE[] SEC("license") = "GPL";
