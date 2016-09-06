package waterutil

import (
	"encoding/binary"
	"net"
)

func IPChecksum(header []byte) uint16 {
	var buf []byte

	sum := uint32(0)
	copy(buf, header)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}

	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	csum := ^uint16(sum)

	if csum == 0 {
		csum = 0xffff
	}

	return csum
}

func ICMPv6PseudoHeader(source net.IP, dest net.IP, length uint32) []byte {
	packet = make([]byte, 80)

	copy(packet[0:32], source.To16())
	copy(packet[32:64], dest.To16())
	// This is fraught with issues, probably. See golang.org/x/net/ipv4 Marshal
	binary.BigEndian.PutUint32(packet[64:74], length)
	copy(packet[74:78], 0)
	copy(packet[78:80], 58)

	return packet
}

// The Checksum helper functions assume all the other packet values are correct

func setTCPv4Checksum(packet []byte) {
	var calc []byte

	copy(calc, packet)

	// Set TTL and Checksum to zero
	calc[8] = 0
	calc[10:12] = 0

	csum := IPChecksum(calc)

	calc[10:12] = csum

	copy(packet, calc)
}

func setTCPv6Checksum(packet []byte) {
	var calc []byte

	copy(calc, packet)

	// Set some header values
	calc[36:40] = 0
	calc[40] = 6
	calc[56:58] = 0

	csum := IPChecksum(calc)

	calc[56:58] = csum

	copy(packet, calc)
}

func setUDPv4Checksum(packet []byte) {
	var calc []byte

	copy(calc, packet)

	// Set TTL and Checksum to zero
	calc[8] = 0     //Zero Field
	calc[18:20] = 0 // Checksum

	csum := IPChecksum(calc)

	calc[18:20] = csum

	copy(packet, calc)
}

func setUDPv6Checksum(packet []byte) {
	var calc []byte

	copy(calc, packet)

	// Set some header values
	calc[36:39] = 0 // Zero field
	calc[39] = 17   //It's UDP
	calc[46:48] = 0 // Checksum

	csum := IPChecksum(calc)

	calc[46:48] = csum

	copy(packet, calc)
}
