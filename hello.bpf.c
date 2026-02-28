#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    // Declare the string as a static array to avoid .rodata.str1.1
    static const char msg[] = "Hello World from WSL2 Kernel!";
    
    // Use the underlying trace function directly
    bpf_trace_printk(msg, sizeof(msg));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";