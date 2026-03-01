#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 1. Define the data we want to send to user-space
struct event {
    int pid;
    char comm[16]; // The name of the process
};

// 2. Create the Ring Buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    struct event *e;

    // 3. Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0; // Buffer full, drop the event
    }

    // 4. Fill in the event data
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 5. Submit the event to user-space
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";