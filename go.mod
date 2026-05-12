// Module path kept as upstream (x86taka) for import compatibility.
// The Containerfile uses a replace directive for the amaumene fork.
module github.com/x86taka/xdp-etherip

go 1.24.0

toolchain go1.26.0

require (
	github.com/cilium/ebpf v0.20.0
	github.com/google/go-cmp v0.7.0
	github.com/google/gopacket v1.1.19
	github.com/urfave/cli/v3 v3.6.2
	github.com/vishvananda/netlink v1.3.1
)

require (
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

// gopacket fork adds layers.EtherIP (RFC 3378) type used in BPF tests.
// Upstream: https://github.com/google/gopacket.
replace github.com/google/gopacket v1.1.19 => github.com/x86taka/gopacket v0.0.0-20231210055638-74b4deb65353
