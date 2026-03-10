package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/urfave/cli/v3"
	"github.com/vishvananda/netlink"
	"github.com/x86taka/xdp-etherip/pkg/coreelf"
	"github.com/x86taka/xdp-etherip/pkg/version"
	"github.com/x86taka/xdp-etherip/pkg/xdptool"
)

func main() {
	cmd := newApp(version.Version)
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.Command {
	return &cli.Command{
		Name:                  "xdp-etherip",
		Version:               version,
		Usage:                 "XDP-based EtherIP tunnel (RFC 3378)",
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "external",
				Usage:    "Tunnel-facing interface name",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "tunnel",
				Usage:    "Tunnel interface name (veth pair auto-created)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "src-ip6",
				Usage:    "Local tunnel endpoint IPv6 address",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "dst-ip6",
				Usage:    "Remote tunnel endpoint IPv6 address",
				Required: true,
			},
		},
		Action: run,
	}
}

func resolveIfindex(device string) (uint32, error) {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return 0, fmt.Errorf("resolve ifindex for %s: %w", device, err)
	}
	return uint32(link.Attrs().Index), nil
}

func parseIPv6ToBytes(addr string) ([16]byte, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return [16]byte{}, fmt.Errorf("invalid IPv6 address: %s", addr)
	}
	ip = ip.To16()
	if ip == nil {
		return [16]byte{}, fmt.Errorf("not an IPv6 address: %s", addr)
	}
	var result [16]byte
	copy(result[:], ip)
	return result, nil
}

func getInterfaceMAC(name string) ([6]byte, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return [6]byte{}, fmt.Errorf("get link %s: %w", name, err)
	}
	hwAddr := link.Attrs().HardwareAddr
	if len(hwAddr) < 6 {
		return [6]byte{}, fmt.Errorf("no MAC address on %s", name)
	}
	var mac [6]byte
	copy(mac[:], hwAddr)
	return mac, nil
}

func resolveNextHop(dstIP net.IP) (net.IP, error) {
	routes, err := netlink.RouteGet(dstIP)
	if err != nil {
		return nil, fmt.Errorf("route lookup %s: %w", dstIP, err)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no route to %s", dstIP)
	}
	if routes[0].Gw != nil {
		return routes[0].Gw, nil
	}
	return dstIP, nil
}

func resolveNeighborMAC(ifindex int, ip net.IP) ([6]byte, error) {
	neighs, err := netlink.NeighList(ifindex, netlink.FAMILY_V6)
	if err != nil {
		return [6]byte{}, fmt.Errorf("list neighbors: %w", err)
	}
	for _, n := range neighs {
		if n.IP.Equal(ip) && len(n.HardwareAddr) >= 6 {
			var mac [6]byte
			copy(mac[:], n.HardwareAddr)
			return mac, nil
		}
	}
	return [6]byte{}, fmt.Errorf("no neighbor entry for %s", ip)
}

const (
	maxRetries = 10
	retryDelay = 500 * time.Millisecond
)

func resolveDstMAC(externalIdx uint32, dstIP net.IP) ([6]byte, error) {
	var nextHop net.IP
	var err error
	for i := range maxRetries {
		if nextHop, err = resolveNextHop(dstIP); err == nil {
			break
		}
		if i < maxRetries-1 {
			log.Printf("retry route %d/%d: %v", i+1, maxRetries, err)
			time.Sleep(retryDelay * time.Duration(i+1))
		}
	}
	if err != nil {
		return [6]byte{}, err
	}
	var mac [6]byte
	for i := range maxRetries {
		if mac, err = resolveNeighborMAC(int(externalIdx), nextHop); err == nil {
			return mac, nil
		}
		if i < maxRetries-1 {
			log.Printf("retry neighbor %d/%d: %v", i+1, maxRetries, err)
			time.Sleep(retryDelay * time.Duration(i+1))
		}
	}
	return mac, err
}

func buildTunnelConfig(cmd *cli.Command, tunnelName, xdpEnd string, tunnelMTU int) (coreelf.TunnelConfig, error) {
	externalDev := cmd.String("external")
	externalIdx, err := resolveIfindex(externalDev)
	if err != nil {
		return coreelf.TunnelConfig{}, err
	}
	internalIdx, err := resolveIfindex(xdpEnd)
	if err != nil {
		return coreelf.TunnelConfig{}, err
	}
	srcAddr, err := parseIPv6ToBytes(cmd.String("src-ip6"))
	if err != nil {
		return coreelf.TunnelConfig{}, err
	}
	dstAddr, err := parseIPv6ToBytes(cmd.String("dst-ip6"))
	if err != nil {
		return coreelf.TunnelConfig{}, err
	}
	dstIP := net.IP(dstAddr[:])
	tunnelMAC, err := getInterfaceMAC(tunnelName)
	if err != nil {
		return coreelf.TunnelConfig{}, err
	}
	externalMAC, err := getInterfaceMAC(externalDev)
	if err != nil {
		return coreelf.TunnelConfig{}, err
	}
	dstMAC, err := resolveDstMAC(externalIdx, dstIP)
	if err != nil {
		return coreelf.TunnelConfig{}, err
	}
	mssV4, mssV6 := coreelf.ComputeMSSClamp(tunnelMTU)
	return coreelf.TunnelConfig{
		SrcAddr:         srcAddr,
		DstAddr:         dstAddr,
		InternalIfindex: internalIdx,
		ExternalIfindex: externalIdx,
		TunnelMAC:       tunnelMAC,
		ExternalMAC:     externalMAC,
		DstMAC:          dstMAC,
		MSSClampIPv4:    mssV4,
		MSSClampIPv6:    mssV6,
	}, nil
}

func attachDevice(prog *ebpf.Program, dev string) error {
	isNative, err := xdptool.Attach(prog, dev)
	if err != nil {
		return fmt.Errorf("attach %s: %w", dev, err)
	}
	if isNative {
		log.Printf("attached device: %s (native/driver)", dev)
	} else {
		log.Printf("attached device: %s (generic/SKB)", dev)
	}
	return nil
}

func dumpDebugCounters(debugMap *ebpf.Map) {
	counters, err := coreelf.ReadDebugCounters(debugMap)
	if err != nil {
		log.Printf("read debug counters: %v", err)
		return
	}
	log.Println("--- debug counters ---")
	for i, name := range coreelf.DebugCounterNames {
		if counters[i] > 0 {
			log.Printf("  %s: %d", name, counters[i])
		}
	}
	log.Println("--- end counters ---")
}

func waitForSignal(devices []string, tunnelName string, debugMap *ebpf.Map) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")
	<-signalChan
	dumpDebugCounters(debugMap)
	return cleanup(devices, tunnelName)
}

func cleanup(devices []string, tunnelName string) error {
	for _, dev := range devices {
		if err := xdptool.Detach(dev); err != nil {
			log.Printf("detach %s: %v", dev, err)
		}
		log.Println("detach device:", dev)
	}
	if err := xdptool.DeleteVethPair(tunnelName); err != nil {
		return fmt.Errorf("delete veth pair: %w", err)
	}
	log.Println("deleted veth pair:", tunnelName)
	return nil
}

func loadAndAttach(externalDev string, cfg *coreelf.TunnelConfig, xdpEnd string) ([]string, *ebpf.Map, func(), error) {
	obj, err := coreelf.ReadCollection()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load ebpf: %w", err)
	}
	if err := coreelf.PopulateTunnelConfig(obj.TunnelConfigMap, *cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("populate tunnel config: %w", err)
	}
	if err := coreelf.PopulateRedirectDevmap(obj.RedirectDevmap, cfg.ExternalIfindex, cfg.InternalIfindex); err != nil {
		return nil, nil, nil, fmt.Errorf("populate redirect devmap: %w", err)
	}
	if err := attachDevice(obj.XdpProg, xdpEnd); err != nil {
		return nil, nil, nil, err
	}
	if err := attachDevice(obj.XdpProg, externalDev); err != nil {
		if detachErr := xdptool.Detach(xdpEnd); detachErr != nil {
			log.Printf("detach %s after partial attach: %v", xdpEnd, detachErr)
		}
		return nil, nil, nil, err
	}
	devices := []string{externalDev, xdpEnd}
	closeFn := func() { obj.Close() }
	return devices, obj.DebugCounters, closeFn, nil
}

func setupTunnel(cmd *cli.Command) (string, string, int, error) {
	tunnelName := cmd.String("tunnel")
	tunnelMTU, err := xdptool.TunnelMTU(cmd.String("external"))
	if err != nil {
		return "", "", 0, fmt.Errorf("compute tunnel mtu: %w", err)
	}
	xdpEnd, err := xdptool.CreateVethPair(tunnelName, tunnelMTU)
	if err != nil {
		return "", "", 0, fmt.Errorf("create veth pair: %w", err)
	}
	log.Printf("created veth pair: %s <-> %s (mtu %d)", tunnelName, xdpEnd, tunnelMTU)
	return tunnelName, xdpEnd, tunnelMTU, nil
}

func run(ctx context.Context, cmd *cli.Command) (retErr error) {
	tunnelName, xdpEnd, tunnelMTU, err := setupTunnel(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			if delErr := xdptool.DeleteVethPair(tunnelName); delErr != nil {
				log.Printf("cleanup veth %s: %v", tunnelName, delErr)
			}
		}
	}()
	cfg, err := buildTunnelConfig(cmd, tunnelName, xdpEnd, tunnelMTU)
	if err != nil {
		return err
	}
	passProg, err := xdptool.CreatePassProg()
	if err != nil {
		return fmt.Errorf("create pass program: %w", err)
	}
	defer passProg.Close()
	if err := attachDevice(passProg, tunnelName); err != nil {
		return err
	}
	devices, debugMap, closeBPF, err := loadAndAttach(cmd.String("external"), &cfg, xdpEnd)
	if err != nil {
		return err
	}
	defer closeBPF()
	devices = append(devices, tunnelName)
	log.Printf("tunnel config: tunnel_mac=%x external_mac=%x dst_mac=%x",
		cfg.TunnelMAC, cfg.ExternalMAC, cfg.DstMAC)
	log.Printf("tunnel interface %s is ready", tunnelName)
	return waitForSignal(devices, tunnelName, debugMap)
}
