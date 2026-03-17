package xdptool

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
)

const xdpPass = 2

const (
	ifnamsiz           = 15
	xdpPeerSuffix      = "-xdp"
	xdpFlagsDRVMode    = 1 << 2
	xdpFlagsSKBMode    = 1 << 1
	tunnelOverhead     = 56 // outer IPv6 (40) + EtherIP (2) + inner Ethernet (14)
	siocETHTOOL        = 0x8946
	ethtoolGetFeatures = 0x3a
	ethtoolSetFeatures = 0x3b
	maxFeatureWords    = 8
	netifFIPCsumBit    = 1
	netifFHWCsumBit    = 3
	netifFIPV6CsumBit  = 4
)

func xdpPeerName(name string) string {
	return name + xdpPeerSuffix
}

func TunnelMTU(externalDev string) (int, error) {
	link, err := netlink.LinkByName(externalDev)
	if err != nil {
		return 0, fmt.Errorf("get link %s: %w", externalDev, err)
	}
	return link.Attrs().MTU - tunnelOverhead, nil
}

func setMTU(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find link %s: %w", name, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("set mtu on %s: %w", name, err)
	}
	return nil
}

func disableTxOffload(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("open socket: %w", err)
	}
	defer syscall.Close(fd)
	words, err := queryFeatureWords(fd, name)
	if err != nil {
		return err
	}
	return clearTxChecksum(fd, name, words)
}

func queryFeatureWords(fd int, name string) (uint32, error) {
	buf := make([]byte, 4+4+maxFeatureWords*16)
	binary.NativeEndian.PutUint32(buf[0:4], ethtoolGetFeatures)
	binary.NativeEndian.PutUint32(buf[4:8], maxFeatureWords)
	if err := ethtoolIoctl(fd, name, buf); err != nil {
		return 0, fmt.Errorf("get features on %s: %w", name, err)
	}
	return binary.NativeEndian.Uint32(buf[4:8]), nil
}

func clearTxChecksum(fd int, name string, words uint32) error {
	buf := make([]byte, 4+4+words*8)
	binary.NativeEndian.PutUint32(buf[0:4], ethtoolSetFeatures)
	binary.NativeEndian.PutUint32(buf[4:8], words)
	mask := uint32(1<<netifFIPCsumBit | 1<<netifFHWCsumBit | 1<<netifFIPV6CsumBit)
	binary.NativeEndian.PutUint32(buf[8:12], mask)
	binary.NativeEndian.PutUint32(buf[12:16], 0)
	if err := ethtoolIoctl(fd, name, buf); err != nil {
		return fmt.Errorf("set features on %s: %w", name, err)
	}
	return nil
}

func ethtoolIoctl(fd int, name string, data []byte) error {
	type ifreq struct {
		name [16]byte
		data unsafe.Pointer
		_pad [16]byte // fill to 40 bytes (sizeof struct ifreq)
	}
	var req ifreq
	copy(req.name[:], name)
	req.data = unsafe.Pointer(&data[0])
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocETHTOOL, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}
	return nil
}

func configureVethPair(name, peerName string, mtu int) error {
	if err := setMTU(name, mtu); err != nil {
		return err
	}
	if err := setMTU(peerName, mtu); err != nil {
		return err
	}
	if err := disableTxOffload(name); err != nil {
		return err
	}
	if err := bringUpLink(name); err != nil {
		return err
	}
	return bringUpLink(peerName)
}

func deleteIfExists(name string) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	netlink.LinkDel(link)
}

func CreateVethPair(name string, mtu int) (string, error) {
	peerName := xdpPeerName(name)
	if err := validateVethNames(name, peerName); err != nil {
		return "", err
	}
	deleteIfExists(name)
	deleteIfExists(peerName)
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  peerName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return "", fmt.Errorf("create veth pair %s/%s: %w", name, peerName, err)
	}
	if err := configureVethPair(name, peerName, mtu); err != nil {
		return "", err
	}
	return peerName, nil
}

func DeleteVethPair(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find veth %s for deletion: %w", name, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete veth %s: %w", name, err)
	}
	return nil
}

func validateVethNames(name, peerName string) error {
	if len(name) > ifnamsiz {
		return fmt.Errorf("interface name %q exceeds %d characters", name, ifnamsiz)
	}
	if len(peerName) > ifnamsiz {
		return fmt.Errorf("peer name %q exceeds %d characters (base name max %d)", peerName, ifnamsiz, ifnamsiz-len(xdpPeerSuffix))
	}
	return nil
}

func bringUpLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find link %s: %w", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	return nil
}

func CreatePassProg() (*ebpf.Program, error) {
	spec := &ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, xdpPass),
			asm.Return(),
		},
		License: "Dual MIT/GPL",
	}
	return ebpf.NewProgram(spec)
}

func Attach(prog *ebpf.Program, device string) (bool, error) {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return false, fmt.Errorf("%s not found: %w", device, err)
	}
	netlink.LinkSetXdpFdWithFlags(link, -1, xdpFlagsSKBMode)
	netlink.LinkSetXdpFdWithFlags(link, -1, xdpFlagsDRVMode)
	nativeErr := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), xdpFlagsDRVMode)
	if nativeErr == nil {
		return true, nil
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), xdpFlagsSKBMode); err != nil {
		return false, fmt.Errorf("attach %s (native: %v): %w", device, nativeErr, err)
	}
	return false, nil
}

func Detach(device string) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("find link %s: %w", device, err)
	}
	netlink.LinkSetXdpFdWithFlags(link, -1, xdpFlagsSKBMode)
	netlink.LinkSetXdpFdWithFlags(link, -1, xdpFlagsDRVMode)
	return nil
}
