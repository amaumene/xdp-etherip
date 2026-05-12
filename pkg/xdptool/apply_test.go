package xdptool

import (
	"testing"
)

func TestValidateVethNames(t *testing.T) {
	tests := []struct {
		name    string
		peer    string
		wantErr bool
	}{
		{"ok", "eth0", "eth0-xdp", false},
		{"short names", "a", "a-xdp", false},
		{"too long base", "0123456789abcdef", "0123456789abcdef-xdp", true},
		{"too long peer", "short", "this-name-is-way-too-long", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVethNames(tt.name, tt.peer)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateVethNames(%q, %q) error = %v, wantErr = %v",
					tt.name, tt.peer, err, tt.wantErr)
			}
		})
	}
}

func TestXdpPeerName(t *testing.T) {
	got := xdpPeerName("tunnel0")
	want := "tunnel0-xdp"
	if got != want {
		t.Errorf("xdpPeerName(tunnel0) = %q, want %q", got, want)
	}
}
