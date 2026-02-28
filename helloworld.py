from bcc import BPF

# 1. The Kernel Program (C code inside a string)
program = """
int hello(void *ctx) {
    bpf_trace_printk("Hello World from BCC!\\n");
    return 0;
}
"""

# 2. Load the program and attach it to a kprobe (kernel function entry)
# We'll attach it to the 'execve' system call
b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello")

# 3. Print the output
print("Tracing execve()... Ctrl-C to stop.")
try:
    b.trace_print()
except KeyboardInterrupt:
    exit()