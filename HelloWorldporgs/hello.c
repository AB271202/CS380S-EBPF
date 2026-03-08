#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"
#include <string.h>
// 1. Define the exact same struct here in user-space
struct event {
    int pid;
    char comm[16];
};

// 2. Create a callback function to handle incoming events
int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    printf("Exec event intercepted! PID: %d | Command: %s\n", e->pid, e->comm);
    return 0;
}

int main() {
    struct hello_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    skel = hello_bpf__open_and_load();
    if (!skel) return 1;

    err = hello_bpf__attach(skel);
    if (err) goto cleanup;

    // 3. Set up the ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        printf("Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("BPF program running! Listening for events directly in the terminal...\n");
    printf("Open another terminal and run commands like 'ls' or 'date'.\n");
    printf("Press Ctrl+C to stop.\n\n");

    // 4. Continuously poll the buffer instead of sleeping
    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    hello_bpf__destroy(skel);
    return 0;
}