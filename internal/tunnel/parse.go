package tunnel

import (
	"fmt"
	"net"
)

// ParseIPv6ToBytes parses an IPv6 address string and returns it as a
// 16-byte array. Returns an error for invalid addresses or IPv4-only
// addresses.
func ParseIPv6ToBytes(addr string) ([16]byte, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return [16]byte{}, fmt.Errorf("invalid IPv6 address: %s", addr)
	}
	if ip.To4() != nil {
		return [16]byte{}, fmt.Errorf("not an IPv6 address: %s", addr)
	}
	ip = ip.To16()
	if ip == nil {
		return [16]byte{}, fmt.Errorf("not an IPv6 address: %s", addr)
	}
	var result [16]byte
	copy(result[:], ip)
	return result, nil
}
