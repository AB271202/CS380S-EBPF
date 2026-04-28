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

// Key for fd-to-filename mapping: combines pid and fd.
struct pid_fd_t {
    u32 pid;
    u32 fd;
};

BPF_PERF_OUTPUT(events);

// Maps fd (per-process) to the filename it was opened with.
BPF_HASH(fd_to_filename, struct pid_fd_t, struct filename_t);

// Temporary storage for open() entry: saves filename until kretprobe gets the fd.
BPF_HASH(open_entry, u64, struct filename_t);

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

// --- Open: entry saves filename, return associates it with the fd ---

int kprobe__do_sys_openat2(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    struct filename_t fname = {};
    bpf_probe_read_user_str(&fname.s, sizeof(fname.s), filename);

    // Early filter: skip system/virtual paths.
    if (fname.s[0] == '/') {
        char c1 = fname.s[1];
        if (c1 == 'p' && fname.s[2] == 'r' && fname.s[3] == 'o' &&
            fname.s[4] == 'c' && fname.s[5] == '/') {
            return 0;  // /proc/
        }
        if (c1 == 's' && fname.s[2] == 'y' && fname.s[3] == 's' &&
            fname.s[4] == '/') {
            return 0;  // /sys/
        }
        if (c1 == 'r' && fname.s[2] == 'u' && fname.s[3] == 'n' &&
            fname.s[4] == '/') {
            return 0;  // /run/
        }
    }

    // Save filename for the kretprobe to pick up.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    open_entry.update(&pid_tgid, &fname);

    // Emit OPEN event (and check for urandom).
    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    populate_process_info(event);
    event->type = EVENT_OPEN;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel(&event->filename, sizeof(event->filename), fname.s);

    // Detect /dev/urandom or /dev/random access.
    if (fname.s[0] == '/' && fname.s[1] == 'd' &&
        fname.s[2] == 'e' && fname.s[3] == 'v' &&
        fname.s[4] == '/') {
        if ((fname.s[5] == 'u' && fname.s[6] == 'r' &&
             fname.s[7] == 'a' && fname.s[8] == 'n' &&
             fname.s[9] == 'd' && fname.s[10] == 'o' &&
             fname.s[11] == 'm') ||
            (fname.s[5] == 'r' && fname.s[6] == 'a' &&
             fname.s[7] == 'n' && fname.s[8] == 'd' &&
             fname.s[9] == 'o' && fname.s[10] == 'm')) {
            event->type = EVENT_URANDOM_READ;
            events.perf_submit(ctx, event, sizeof(*event));
            return 0;
        }
    }

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int kretprobe__do_sys_openat2(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = PT_REGS_RC(ctx);

    // Negative return means open failed — no fd to track.
    if (fd < 0) {
        open_entry.delete(&pid_tgid);
        return 0;
    }

    struct filename_t *fname = open_entry.lookup(&pid_tgid);
    if (!fname) {
        return 0;
    }

    // Associate this fd with the filename.
    struct pid_fd_t key = {};
    key.pid = pid_tgid >> 32;
    key.fd = (u32)fd;
    fd_to_filename.update(&key, fname);

    open_entry.delete(&pid_tgid);
    return 0;
}

// --- Write: look up filename by (pid, fd) ---

int kprobe__ksys_write(struct pt_regs *ctx) {
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    if (count < MIN_WRITE_SIZE) {
        return 0;
    }

    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    populate_process_info(event);
    event->type = EVENT_WRITE;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Look up filename by (pid, fd).
    struct pid_fd_t key = {};
    key.pid = pid_tgid >> 32;
    key.fd = fd;
    struct filename_t *fname = fd_to_filename.lookup(&key);
    if (!fname) {
        return 0;
    }
    bpf_probe_read_kernel(&event->filename, sizeof(event->filename), fname->s);

    // Early filter: skip writes to system/virtual paths.
    if (event->filename[0] == '/') {
        char c1 = event->filename[1];
        if (c1 == 'd' && event->filename[2] == 'e' && event->filename[3] == 'v' &&
            event->filename[4] == '/') {
            return 0;  // /dev/
        }
        if (c1 == 'p' && event->filename[2] == 'r' && event->filename[3] == 'o' &&
            event->filename[4] == 'c' && event->filename[5] == '/') {
            return 0;  // /proc/
        }
        if (c1 == 's' && event->filename[2] == 'y' && event->filename[3] == 's' &&
            event->filename[4] == '/') {
            return 0;  // /sys/
        }
        if (c1 == 'r' && event->filename[2] == 'u' && event->filename[3] == 'n' &&
            event->filename[4] == '/') {
            return 0;  // /run/
        }
    }

    event->size = count;
    bpf_probe_read_user(&event->buffer, sizeof(event->buffer), buf);

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// --- Rename ---

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

int kprobe__do_renameat2(struct pt_regs *ctx) {
    const char *newname = (const char *)PT_REGS_PARM4(ctx);
    return trace_rename(ctx, newname);
}

// --- Unlink ---

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

int kprobe__do_unlinkat(struct pt_regs *ctx) {
    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);
    return trace_unlink(ctx, name);
}

// --- Getdents (directory listing) ---

int kprobe__iterate_dir(struct pt_regs *ctx) {
    struct event_t *event = get_event();
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    populate_process_info(event);
    event->type = EVENT_GETDENTS;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // For getdents, use the fd from the first argument (the directory fd).
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    struct pid_fd_t key = {};
    key.pid = pid_tgid >> 32;
    key.fd = fd;
    struct filename_t *fname = fd_to_filename.lookup(&key);
    if (fname) {
        bpf_probe_read_kernel(&event->filename, sizeof(event->filename), fname->s);
    }

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// --- Kill signal delivery ---

int kprobe__do_send_sig_info(struct pt_regs *ctx) {
    struct event_t *event = get_event();
    if (!event) return 0;

    int sig = (int)PT_REGS_PARM1(ctx);
    struct task_struct *target = (struct task_struct *)PT_REGS_PARM3(ctx);

    // Only track SIGKILL (9), SIGTERM (15), and SIGSTOP (19).
    if (sig != 9 && sig != 15 && sig != 19) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));

    populate_process_info(event);
    event->type = EVENT_KILL;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->size = sig;

    if (target) {
        bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename),
                                  &target->comm);
    }

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
