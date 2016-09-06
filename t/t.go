package main

import (
	"fmt"
	"github.com/flynn/go-wireguard"
	"github.com/nnathan/water"
	"log"
	"net"
	"os"
)

func main() {
	tun, err := water.NewTUN("")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on 0.0.0.0:55555")
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 55555})
	if err != nil {
		log.Fatal(err)
	}

	// privkey: c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669 / yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
	// pubkey:  1c8828f7137324c58b2804928624ea2326f1674537c062e251e2753ca7fcca4c / HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
	priv := []byte{0xc8, 0x09, 0xf3, 0xe5, 0x31, 0x7e, 0x95, 0x75, 0xc9, 0xb5, 0xed, 0x78, 0xb6, 0x38, 0xb7, 0xce, 0x53, 0x0d, 0xab, 0xe8, 0x5d, 0xda, 0xb6, 0x14, 0x22, 0x02, 0x41, 0x80, 0x1d, 0xdf, 0x06, 0x69}

	config := wireguard.InterfaceConfig{Outside: uc, Inside: tun, PrivateKey: priv, PresharedKey: nil, Peers: nil}

	i, err := wireguard.NewInterface(config)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface.Run(): going into packet receive loop")
	i.Run()
}
