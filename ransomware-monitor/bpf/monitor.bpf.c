#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

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

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 zero = 0;
    struct event_t *event = event_heap.lookup(&zero);
    if (!event) return 0;

    // Reset event data
    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->type = EVENT_OPEN;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->filename);
    
    events.perf_submit(args, event, sizeof(*event));
    
    struct filename_t fname = {};
    bpf_probe_read_kernel(&fname.s, sizeof(fname.s), event->filename);
    fd_to_filename.update(&pid_tgid, &fname);
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 zero = 0;
    struct event_t *event = event_heap.lookup(&zero);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->type = EVENT_WRITE;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    struct filename_t *fname = fd_to_filename.lookup(&pid_tgid);
    if (fname) {
        bpf_probe_read_kernel(&event->filename, sizeof(event->filename), fname->s);
    }

    event->size = args->count;
    bpf_probe_read_user(&event->buffer, sizeof(event->buffer), args->buf);
    
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    u32 zero = 0;
    struct event_t *event = event_heap.lookup(&zero);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->type = EVENT_RENAME;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->newname);
    
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    u32 zero = 0;
    struct event_t *event = event_heap.lookup(&zero);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->type = EVENT_UNLINK;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->pathname);
    
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}
