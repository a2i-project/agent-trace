package net

// Same -I flag rationale as pkg/probe/proc: points clang at the multiarch
// UAPI headers, matching both local dev and the x86_64 CI runner.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type net_event_hdr bpf net.bpf.c -- -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type ssl_frame_hdr -type ssl_write_counts tlsbpf tls.bpf.c -- -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86
