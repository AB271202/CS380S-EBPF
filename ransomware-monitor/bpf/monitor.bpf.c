#include <uapi/linux/ptrace.h>
#include <uapi/linux/fcntl.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MIN_WRITE_SIZE 64

struct open_how_t {
    u64 flags;
    u64 mode;
    u64 resolve;
};

enum event_type {
    EVENT_OPEN,
    EVENT_WRITE,
    EVENT_RENAME,
    EVENT_UNLINK
};

struct event_t {
    u32 pid;
    enum event_type type;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u64 size;
    u8 buffer[128];
};

struct filename_t {
    char s[256];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(fd_to_filename, u64, struct filename_t);

// Use a per-CPU array as a scratch buffer to stay under the 512-byte stack limit
BPF_PERCPU_ARRAY(event_heap, struct event_t, 1);

static __always_inline struct event_t *get_event(void) {
    u32 zero = 0;
    return event_heap.lookup(&zero);
}

static __always_inline int trace_open(struct pt_regs *ctx, const char *filename, int flags) {
    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->type = EVENT_OPEN;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);

    // Keep filename state for write correlation.
    struct filename_t fname = {};
    bpf_probe_read_kernel(&fname.s, sizeof(fname.s), event->filename);
    fd_to_filename.update(&pid_tgid, &fname);

    if (!(flags & O_CREAT)) {
        return 0;
    }

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

static __always_inline int trace_write(struct pt_regs *ctx, const char *buf, size_t count) {
    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (count < MIN_WRITE_SIZE) {
        return 0;
    }

    event->pid = pid_tgid >> 32;
    event->type = EVENT_WRITE;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    struct filename_t *fname = fd_to_filename.lookup(&pid_tgid);
    if (!fname) {
        return 0;
    }
    bpf_probe_read_kernel(&event->filename, sizeof(event->filename), fname->s);

    event->size = count;
    bpf_probe_read_user(&event->buffer, sizeof(event->buffer), buf);

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

static __always_inline int trace_rename(struct pt_regs *ctx, const char *newname) {
    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->type = EVENT_RENAME;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), newname);

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// WSL's current BCC/kernel combination does not expose usable syscall
// tracepoint arg structs, and kprobes on __x64_sys_* wrappers require an extra
// pt_regs unwrap that the verifier rejects. Hook direct kernel helpers instead.
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    struct open_how_t *how_ptr = (struct open_how_t *)PT_REGS_PARM3(ctx);
    struct open_how_t how = {};
    bpf_probe_read_kernel(&how, sizeof(how), how_ptr);
    return trace_open(ctx, filename, (int)how.flags);
}

int kprobe__ksys_write(struct pt_regs *ctx) {
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    return trace_write(ctx, buf, count);
}

int kprobe__do_renameat2(struct pt_regs *ctx) {
    const char *newname = (const char *)PT_REGS_PARM4(ctx);
    return trace_rename(ctx, newname);
}
