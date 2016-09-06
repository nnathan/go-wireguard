//TODO: Need to add ICMP, specifically ICMP unreachable
//
// Yes, I know there's golang.org/x/net/ipv6
// It doesn't do header marshaling.
// So, somewhat useless

package waterutil

import (
	"net"
)

func IPv6HopLimit(packet []byte) byte {
	return packet[7]
}

func IPv6NextHeader(packet []byte) IPProtocol {
	return IPProtocol(packet[6])
}

func IPv6Source(packet []byte) net.IP {
	return packet[8:24]
}

func SetIPv6Source(packet []byte, source net.IP) {
	copy(packet[12:16], source)
}

func IPv6Destination(packet []byte) net.IP {
	return packet[24:40]
}

func SetIPv6Destination(packet []byte, dest net.IP) {
	copy(packet[16:20], dest.To4())
}

func IPv6Payload(packet []byte) []byte {
	return packet[160:]
}

// For TCP/UDP
func IPv6SourcePort(packet []byte) uint16 {
	payload := IPv6Payload(packet)
	return (uint16(payload[0]) << 8) | uint16(payload[1])
}

func IPv6DestinationPort(packet []byte) uint16 {
	payload := IPv6Payload(packet)
	return (uint16(payload[2]) << 8) | uint16(payload[3])
}

func SetIPv6SourcePort(packet []byte, port uint16) {
	payload := IPv6Payload(packet)
	payload[0] = byte(port >> 8)
	payload[1] = byte(port & 0xFF)
}

func SetIPv6DestinationPort(packet []byte, port uint16) {
	payload := IPv6Payload(packet)
	payload[2] = byte(port >> 8)
	payload[3] = byte(port & 0xFF)
}
