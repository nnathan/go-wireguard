package main

import (
	"fmt"
	"github.com/chromicant/water"
	"github.com/flynn/go-wireguard"
	"log"
	"net"
	"os"
)

func main() {
	fmt.Printf("%d\n", os.Getpid())
	tun, err := water.NewTUN("")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v, %v\n\n", err, tun)
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v, %v\n\n", err, *uc)
	// yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
	priv := []byte{0xc8, 0x09, 0xf3, 0xe5, 0x31, 0x7e, 0x95, 0x75, 0xc9, 0xb5, 0xed, 0x78, 0xb6, 0x38, 0xb7, 0xce, 0x53, 0x0d, 0xab, 0xe8, 0x5d, 0xda, 0xb6, 0x14, 0x22, 0x02, 0x41, 0x80, 0x1d, 0xdf, 0x06, 0x69}

	config := wireguard.InterfaceConfig{Outside: uc, Inside: tun, PrivateKey: priv, PresharedKey: nil, Peers: nil}

	i, err := wireguard.NewInterface(config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(i)
	i.Run()
}
