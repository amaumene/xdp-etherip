package tunnel_test

import (
	"testing"

	"github.com/x86taka/xdp-etherip/pkg/tunnel"
)

func TestParseIPv6ToBytes(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"valid", "fe80::1", false},
		{"valid full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"abbreviated", "2001:db8::1", false},
		{"empty", "", true},
		{"invalid char", "not-an-ip", true},
		{"ipv4", "192.168.1.1", true},
		{"ipv4 mapped", "::ffff:192.0.2.1", true}, // IPv4-mapped, not a real IPv6
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tunnel.ParseIPv6ToBytes(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPv6ToBytes(%q) error = %v, wantErr = %v",
					tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestComputeMSSClamp(t *testing.T) {
	tests := []struct {
		name      string
		mtu       int
		wantMSSv4 uint16
		wantMSSv6 uint16
	}{
		{"1444 tunnel mtu", 1444, 1404, 1384},
		{"1280 tunnel mtu", 1280, 1240, 1220},
		{"too small", 70, 0, 0},
		{"exactly min", 80, 40, 20}, // 80-20-20=40, 80-40-20=20
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v4, v6 := tunnel.ComputeMSSClamp(tt.mtu)
			if v4 != tt.wantMSSv4 {
				t.Errorf("IPv4 MSS = %d, want %d", v4, tt.wantMSSv4)
			}
			if v6 != tt.wantMSSv6 {
				t.Errorf("IPv6 MSS = %d, want %d", v6, tt.wantMSSv6)
			}
		})
	}
}
