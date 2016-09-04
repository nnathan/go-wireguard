package wireguard

import "log"
import "fmt"
import "runtime"

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

func (f *Interface) receiveInsidePacket(buf []byte) {
	fmt.Printf("%d %x\n", len(buf), buf)
}
