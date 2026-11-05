package fs

// vmlinux.h is generated from the BTF of kernel 7.0, which declares the file
// dynptr kfuncs the kernel content copy calls (P-48). The -I flag points clang
// at the multiarch UAPI headers, as in pkg/probe/proc.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type khash_hdr -type khash_counts khash khash.bpf.c -- -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -Wno-missing-declarations
