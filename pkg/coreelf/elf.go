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
	Pad             [2]byte
	MSSClampIPv4    uint16
	MSSClampIPv6    uint16
}

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	tcpHeaderLen  = 20
)

func ComputeMSSClamp(tunnelMTU int) (uint16, uint16) {
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

const (
	DbgEncapEnter      = 0
	DbgEncapAdjustFail = 1
	DbgEncapBuildFail  = 2
	DbgEncapMssFail    = 3
	DbgEncapBoundsFail = 4
	DbgEncapRedirect   = 5
	DbgDecapEnter      = 6
	DbgDecapNotIPv6    = 7
	DbgDecapNotEtherIP = 8
	DbgDecapOwnPkt     = 9
	DbgDecapBadHeader  = 10
	DbgDecapRedirect   = 11
	DbgMainEnter       = 12
	DbgMainNoCfg       = 13
	DbgMax             = 14
)

var DebugCounterNames = [DbgMax]string{
	"encap_enter", "encap_adjust_fail", "encap_build_fail",
	"encap_mss_fail", "encap_bounds_fail", "encap_redirect",
	"decap_enter", "decap_not_ipv6", "decap_not_etherip",
	"decap_own_pkt", "decap_bad_header", "decap_redirect",
	"main_enter", "main_no_cfg",
}

func ReadDebugCounters(m *ebpf.Map) ([DbgMax]uint64, error) {
	var counters [DbgMax]uint64
	for i := uint32(0); i < DbgMax; i++ {
		var vals []uint64
		if err := m.Lookup(i, &vals); err != nil {
			return counters, fmt.Errorf("read counter %d: %w", i, err)
		}
		for _, v := range vals {
			counters[i] += v
		}
	}
	return counters, nil
}
