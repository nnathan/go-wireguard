package wireguard

import (
	"errors"
	"log"
	"net"
	"runtime"
)

var ErrHostUnreachable = errors.New("Host unreachable")

// TODO: be smarter about this
const mtu = 1500

func (f *Interface) readInsidePackets() {
	mtu := mtu
	skip := 0

	// OSX prepends the first 4 bytes received by each packet
	// with the values of AF_INET/AF_INET6 to indicate the
	// encapsulated IP packet. Unfortunately a Read()
	// must be for the entire packet content before fetching
	// subsequent packets, therefore we need to do a little
	// massaging ourselves.
	if runtime.GOOS == "darwin" {
		mtu += 4
		skip = 4
	}

	for {
		buf := make([]byte, mtu)
		log.Println("wip: f.inside.Read()\n")
		n, err := f.inside.Read(buf)
		log.Printf("wip: f.inside.Read() finished: (%d, %s)\n", n, err)
		if err != nil {
			// TODO: figure out what kind of errors can be returned
			// one would be unloading the TUN driver from underneath
			log.Printf("f.inside.Read() error: %s\n", err)
			continue
		}

		f.receiveInsidePacket(buf[skip:n])
	}
}

// extracts destination address from IPv4/IPv6 packet
func extractIP(buf []byte) (src net.IP, dst net.IP, err error) {
	ipVer := buf[0] >> 4

	if ipVer == 4 {
		src = net.IP(buf[12:16])
		dst = net.IP(buf[16:20])
	} else if ipVer == 6 {
		src = net.IP(buf[8:24])
		dst = net.IP(buf[24:40])
	} else {
		return src, dst, errInvalidIpPacket
	}

	return src, dst, nil
}

func (f *Interface) receiveInsidePacket(buf []byte) error {
	_, dst, err := extractIP(buf)
	if err != nil {
		return err
	}

	peer, err := f.routetable.Lookup(dst)
	if err != nil {
		return err
	}

	if peer == nil {
		// we need to generate ICMP unreachable message
		// but a bit time consuming to implement at the moment.
		return ErrHostUnreachable
	}

	// in the C implementation [device.c:xmit()] the queue is first
	// trimmed and then the packet is enqueued (after being segmented
	// using GSO); it is unclear (but probably unlikely) we need to
	// do segmentation as the underlying TUN driver will do this for us;
	// (and fairly easy to test).
	peer.txQueue.BoundedAppend(buf, maxQueuePackets)

	return peer.sendQueue()
}
