TARGET := hello
BPF_OBJ := $(TARGET).bpf.o
BPF_C := $(TARGET).bpf.c
USER_C := $(TARGET).c
SKEL := $(TARGET).skel.h

# Find the architecture-specific include path
ARCH_INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu

compile: clean $(TARGET)

# 1. Compile the BPF kernel code
$(BPF_OBJ): $(BPF_C)
	clang -g -O2 -target bpf $(ARCH_INCLUDES) -c $(BPF_C) -o $(BPF_OBJ)
# 	clang -g -O2 -target bpf -fno-merge-constants -I/usr/include/x86_64-linux-gnu -c hello.bpf.c -o hello.bpf.o

# 2. Generate the Skeleton header
$(SKEL): $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(SKEL)

# 3. Compile the User-space loader
$(TARGET): $(SKEL) $(USER_C)
	clang -g -O2 $(USER_C) -lbpf -lelf -lz -o $(TARGET)

mount: 
	sudo mount -t debugfs debugfs /sys/kernel/debug
	sudo mount -t tracefs nodev /sys/kernel/debug/tracing

run:
	sudo ./hello

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(TARGET)
	clear

.PHONY: all clean