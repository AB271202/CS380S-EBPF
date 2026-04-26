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
    EVENT_UNLINK,
    EVENT_GETDENTS,
    EVENT_URANDOM_READ,
    EVENT_KILL
};

struct event_t {
    u32 pid;
    u32 ppid;
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

static __always_inline void populate_process_info(struct event_t *event) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;

    event->pid = pid_tgid >> 32;

    if (!task) {
        return;
    }

    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (!parent) {
        return;
    }

    bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
}

static __always_inline int trace_open(struct pt_regs *ctx, const char *filename, int flags) {
    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    populate_process_info(event);
    event->type = EVENT_OPEN;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);

    // Keep filename state for write correlation.
    struct filename_t fname = {};
    bpf_probe_read_kernel(&fname.s, sizeof(fname.s), event->filename);
    fd_to_filename.update(&pid_tgid, &fname);

    // Detect /dev/urandom or /dev/random access — emit as EVENT_URANDOM_READ.
    // Compare the first 13 bytes: "/dev/urandom\0" or "/dev/random\0".
    if (event->filename[0] == '/' && event->filename[1] == 'd' &&
        event->filename[2] == 'e' && event->filename[3] == 'v' &&
        event->filename[4] == '/') {
        if ((event->filename[5] == 'u' && event->filename[6] == 'r' &&
             event->filename[7] == 'a' && event->filename[8] == 'n' &&
             event->filename[9] == 'd' && event->filename[10] == 'o' &&
             event->filename[11] == 'm') ||
            (event->filename[5] == 'r' && event->filename[6] == 'a' &&
             event->filename[7] == 'n' && event->filename[8] == 'd' &&
             event->filename[9] == 'o' && event->filename[10] == 'm')) {
            event->type = EVENT_URANDOM_READ;
            events.perf_submit(ctx, event, sizeof(*event));
            return 0;
        }
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

    populate_process_info(event);
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

    populate_process_info(event);
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

static __always_inline int trace_unlink(struct pt_regs *ctx, struct filename *name) {
    struct event_t *event = get_event();
    const char *pathname = NULL;
    if (!event || !name) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    populate_process_info(event);
    event->type = EVENT_UNLINK;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_probe_read_kernel(&pathname, sizeof(pathname), &name->name);
    if (!pathname) {
        return 0;
    }
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), pathname);

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

static __always_inline int trace_getdents(struct pt_regs *ctx) {
    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    populate_process_info(event);
    event->type = EVENT_GETDENTS;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Correlate with the last opened filename for this thread.
    struct filename_t *fname = fd_to_filename.lookup(&pid_tgid);
    if (fname) {
        bpf_probe_read_kernel(&event->filename, sizeof(event->filename), fname->s);
    }

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int kprobe__do_renameat2(struct pt_regs *ctx) {
    const char *newname = (const char *)PT_REGS_PARM4(ctx);
    return trace_rename(ctx, newname);
}

int kprobe__do_unlinkat(struct pt_regs *ctx) {
    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);
    return trace_unlink(ctx, name);
}

int kprobe__iterate_dir(struct pt_regs *ctx) {
    return trace_getdents(ctx);
}

// Hook kill/signal delivery to detect ransomware killing security processes.
// do_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p, ...)
int kprobe__do_send_sig_info(struct pt_regs *ctx) {
    struct event_t *event = get_event();
    if (!event) return 0;

    int sig = (int)PT_REGS_PARM1(ctx);
    struct task_struct *target = (struct task_struct *)PT_REGS_PARM3(ctx);

    // Only track SIGKILL (9), SIGTERM (15), and SIGSTOP (19) — the signals
    // ransomware uses to kill or suspend processes.
    if (sig != 9 && sig != 15 && sig != 19) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    populate_process_info(event);
    event->type = EVENT_KILL;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->size = sig;  // Reuse size field for signal number

    // Read the target process's comm into filename field.
    if (target) {
        bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename),
                                  &target->comm);
    }

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
