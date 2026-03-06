# XDP-EtherIP

XDP-accelerated EtherIP tunnel (RFC 3378) over IPv6. Encapsulates Ethernet
frames in IPv6/EtherIP for transport between two endpoints, using XDP for
packet processing on both the physical and virtual interfaces.

Fork of [x86taka/xdp-etherip](https://github.com/x86taka/xdp-etherip) with
a rewritten tunnel architecture targeting embedded routers (tested on
MediaTek MT7986/Filogic 830 running OpenWrt).

## Features

- Ethernet over IPv6 encapsulation (EtherIP, protocol 97)
- TCP MSS clamping for both IPv4 and IPv6 inner packets
- Native XDP (driver mode) with automatic fallback to generic/SKB mode
- DEVMAP-based redirect between physical and tunnel interfaces
- IPv6 extension header handling in decap path
- Loopback protection (drops packets sourced from own address)
- Per-packet debug counters (14 counters across encap/decap paths)
- Cross-compiled static binary via container build (ARM64, x86_64)

## How it works

The program creates a veth pair and attaches an XDP program to both the
physical interface and one end of the veth. A third, minimal XDP program
(XDP_PASS) is attached to the user-facing tunnel interface to satisfy
the kernel's veth redirect requirements.

```
              user space
                  |
           tunnel interface (homenoc)       <- XDP_PASS
                  |  veth pair
           veth peer (homenoc-xdp)          <- main XDP program
                  |  DEVMAP redirect
         physical interface (eth1)          <- main XDP program
                  |
              network
```

**Encap path** (tunnel -> network): Packets entering the veth peer are
wrapped in an outer Ethernet + IPv6 + EtherIP header and redirected to
the physical interface via DEVMAP. TCP SYN packets get their MSS clamped
to fit within the tunnel MTU.

**Decap path** (network -> tunnel): Incoming IPv6/EtherIP packets on the
physical interface have their outer headers stripped and are redirected to
the veth peer via DEVMAP, which delivers them to the tunnel interface.

The tunnel MTU is computed automatically:
```
tunnel_mtu = external_mtu - 56
                             ├── outer Ethernet:  14 bytes
                             ├── IPv6 header:     40 bytes
                             └── EtherIP header:   2 bytes
```

### Why XDP_PASS on the tunnel interface

When the XDP program on the physical interface decapsulates a packet and
redirects it to the veth peer via `bpf_redirect_map`, the kernel calls
`veth_xdp_xmit()` on the peer. This function delivers frames to the
other end of the veth pair (the tunnel interface), but first checks that
the receiving end has an XDP program loaded. Without one, all redirected
frames are silently dropped. The XDP_PASS program exists solely to pass
this check — it accepts every packet without inspection.

## Build

### Container build (recommended)

Produces a static binary without needing BPF toolchain on the host:

```shell
make container-build
# Output: bin/xdp-etherip-static-aarch64
```

### Native build

Requires clang, llvm, libbpf headers, and Go 1.24+.

```shell
# Debian/Ubuntu
sudo apt install clang llvm libelf-dev build-essential \
  linux-headers-$(uname -r) linux-libc-dev libbpf-dev gcc-multilib

# Generate BPF helper headers (if include/ is empty)
./gen_bpf_helper.sh

make
```

## Usage

```shell
xdp-etherip \
  --external eth1 \
  --tunnel homenoc \
  --src-ip6 2001:db8::1 \
  --dst-ip6 2001:db8::2
```

| Flag | Description |
|------|-------------|
| `--external` | Physical interface facing the tunnel peer |
| `--tunnel` | Name for the tunnel interface (veth pair created automatically) |
| `--src-ip6` | Local IPv6 tunnel endpoint |
| `--dst-ip6` | Remote IPv6 tunnel endpoint |

The program resolves the next-hop MAC address from the kernel neighbor
table at startup. Make sure the remote endpoint is reachable (e.g. ping it
first) so the neighbor entry exists.

On exit (SIGINT/SIGTERM), debug counters are printed and all interfaces
are cleaned up.

## Debug counters

The XDP program maintains per-path counters dumped on exit:

| Counter | Meaning |
|---------|---------|
| `main_enter` | Total packets processed |
| `main_no_cfg` | Config map lookup failed |
| `encap_enter` | Entered encap path |
| `encap_redirect` | Successfully redirected to external |
| `encap_adjust_fail` | `bpf_xdp_adjust_head` failed |
| `encap_build_fail` | Outer header construction failed |
| `encap_mss_fail` | MSS clamping failed |
| `encap_bounds_fail` | Bounds check failed after header build |
| `decap_enter` | Entered decap path |
| `decap_redirect` | Successfully redirected to tunnel |
| `decap_not_ipv6` | Packet not IPv6, passed to stack |
| `decap_not_etherip` | IPv6 but not EtherIP, passed to stack |
| `decap_own_pkt` | Loopback detected (own source address) |
| `decap_bad_header` | Invalid EtherIP header |

## Test

```shell
make test
```

Runs the encap test which verifies IPv6/EtherIP header construction and
TCP MSS clamping using cilium/ebpf's test runner. Requires root (the
Makefile passes `-exec sudo`).

## Changes from upstream

Rewritten from [x86taka/xdp-etherip](https://github.com/x86taka/xdp-etherip):

- **New CLI interface**: replaced `--device` multi-flag with explicit
  `--external`, `--tunnel`, `--src-ip6`, `--dst-ip6` flags
- **DEVMAP redirect**: switched from `bpf_redirect` to `bpf_redirect_map`
  with a 2-entry DEVMAP (external + tunnel)
- **Tunnel config map**: single BPF array map holding all tunnel parameters
  (addresses, MACs, ifindices, MSS values), populated from userspace
- **Veth pair management**: automatic creation, MTU configuration, TX
  checksum offload disable, and teardown
- **XDP_PASS on tunnel end**: in-memory BPF program created via
  cilium/ebpf asm to satisfy veth `ndo_xdp_xmit` peer check
- **Native XDP with fallback**: tries driver mode first, falls back to
  generic/SKB, logs which mode is active
- **Mode-specific detach**: detaches both SKB and DRV mode programs before
  attaching, avoids EEXIST on reattach
- **Debug counters**: 14 atomic counters across encap/decap paths, dumped
  on exit
- **IPv6 extension header support**: decap path skips hop-by-hop, routing,
  fragment, and destination option headers
- **Loopback protection**: decap drops packets with own source address
- **Next-hop resolution**: resolves gateway and neighbor MAC via netlink
  at startup
- **Container build**: multi-stage Alpine Containerfile for static
  cross-compilation
- **Dependency updates**: Go 1.26, cilium/ebpf v0.20, urfave/cli v3
