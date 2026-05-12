// Package tunnel provides BPF tunnel configuration helpers and MSS
// clamping computation shared between the CLI and BPF loader.
package tunnel

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	tcpHeaderLen  = 20
)

// ComputeMSSClamp returns the IPv4 and IPv6 MSS clamp values for the
// given tunnel MTU. Returns (0, 0) when the MTU is too small to
// accommodate the tunnel overhead.
func ComputeMSSClamp(tunnelMTU int) (uint16, uint16) {
	const minMTU = ipv6HeaderLen + ipv4HeaderLen + tcpHeaderLen // 80
	if tunnelMTU < minMTU {
		return 0, 0
	}
	return uint16(tunnelMTU - ipv4HeaderLen - tcpHeaderLen),
		uint16(tunnelMTU - ipv6HeaderLen - tcpHeaderLen)
}
