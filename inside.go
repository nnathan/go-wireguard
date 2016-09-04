package wireguard

import "log"
import "fmt"

// TODO: be smarter about this
const mtu = 1500

func (f *Interface) readInsidePackets() {
	for {
		buf := make([]byte, mtu)
		log.Println("wip: f.inside.Read()")
		n, err := f.inside.Read(buf)
		log.Printf("wip: f.inside.Read() finished: (%d, %s)", n, err)
		if err != nil {
			// TODO: figure out what kind of errors can be returned
		}

		// TODO: fire off a goroutine here
		buf = buf[:n]
		f.receiveInsidePacket(buf)
	}
}

func (f *Interface) receiveInsidePacket(buf []byte) {
	fmt.Println("[received packet]")
	fmt.Println(buf)
	fmt.Println("[received packet end]")
}
