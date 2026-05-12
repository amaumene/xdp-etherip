// Package coreelf loads the compiled BPF/XDP program and populates
// its configuration maps: tunnel parameters, redirect devmap, and
// per-CPU debug counters.
package coreelf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf xdp ../../src/xdp_prog.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include -I./../../include -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

type TunnelConfig struct {
	SrcAddr         [16]byte
	DstAddr         [16]byte
	InternalIfindex uint32
	ExternalIfindex uint32
	TunnelMAC       [6]byte
	ExternalMAC     [6]byte
	DstMAC          [6]byte
	_               [2]byte
	MSSClampIPv4    uint16
	MSSClampIPv6    uint16
}

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	tcpHeaderLen  = 20
)

func ComputeMSSClamp(tunnelMTU int) (uint16, uint16) {
	const minMTU = ipv6HeaderLen + ipv4HeaderLen + tcpHeaderLen // 80
	if tunnelMTU < minMTU {
		return 0, 0
	}
	return uint16(tunnelMTU - ipv4HeaderLen - tcpHeaderLen),
		uint16(tunnelMTU - ipv6HeaderLen - tcpHeaderLen)
}

func ReadCollection() (*xdpObjects, error) {
	obj := &xdpObjects{}
	err := loadXdpObjects(obj, nil)
	if err != nil {
		return nil, fmt.Errorf("load xdp objects: %w", err)
	}
	return obj, nil
}

func PopulateTunnelConfig(m *ebpf.Map, cfg TunnelConfig) error {
	if err := m.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("put tunnel config: %w", err)
	}
	return nil
}

const (
	DevmapExternal = 0
	DevmapTunnel   = 1
)

func PopulateRedirectDevmap(m *ebpf.Map, externalIfindex, tunnelIfindex uint32) error {
	if err := m.Put(uint32(DevmapExternal), externalIfindex); err != nil {
		return fmt.Errorf("put devmap external: %w", err)
	}
	if err := m.Put(uint32(DevmapTunnel), tunnelIfindex); err != nil {
		return fmt.Errorf("put devmap tunnel: %w", err)
	}
	return nil
}

// Counter identifies a per-packet debug counter in the BPF program.
type Counter uint32

const (
	EncapEnter      Counter = 0
	EncapAdjustFail Counter = 1
	EncapBuildFail  Counter = 2
	EncapMssFail    Counter = 3
	EncapBoundsFail Counter = 4
	EncapRedirect   Counter = 5
	DecapEnter      Counter = 6
	DecapNotIPv6    Counter = 7
	DecapNotEtherIP Counter = 8
	DecapOwnPkt     Counter = 9
	DecapBadHeader  Counter = 10
	DecapRedirect   Counter = 11
	MainEnter       Counter = 12
	MainNoCfg       Counter = 13
	CounterMax       Counter = 14
)

var counterNames = map[Counter]string{
	EncapEnter:      "encap_enter",
	EncapAdjustFail: "encap_adjust_fail",
	EncapBuildFail:  "encap_build_fail",
	EncapMssFail:    "encap_mss_fail",
	EncapBoundsFail: "encap_bounds_fail",
	EncapRedirect:   "encap_redirect",
	DecapEnter:      "decap_enter",
	DecapNotIPv6:    "decap_not_ipv6",
	DecapNotEtherIP: "decap_not_etherip",
	DecapOwnPkt:     "decap_own_pkt",
	DecapBadHeader:  "decap_bad_header",
	DecapRedirect:   "decap_redirect",
	MainEnter:       "main_enter",
	MainNoCfg:       "main_no_cfg",
}

func (c Counter) String() string {
	if name, ok := counterNames[c]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", c)
}

// DebugCounterNames maps Counter values to human-readable names.
var DebugCounterNames = [CounterMax]string{} // populated from counterNames map

func init() {
	for c, name := range counterNames {
		DebugCounterNames[c] = name
	}
}

func ReadDebugCounters(m *ebpf.Map) ([CounterMax]uint64, error) {
	var counters [CounterMax]uint64
	for i := range CounterMax {
		vals := make([]uint64, 0, 1)
		if err := m.Lookup(uint32(i), &vals); err != nil {
			return counters, fmt.Errorf("read counter %d: %w", i, err)
		}
		for _, v := range vals {
			counters[i] += v
		}
	}
	return counters, nil
}
