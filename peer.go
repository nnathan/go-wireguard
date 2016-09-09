package wireguard

import (
	"net"
	"sync"
	"time"
)

var peerCounter uint64

const maxPeers int = 1<<16 - 1

// A Peer is a remote endpoint that can be communicated with via an Interface.
type Peer struct {
	// PublicKey is the static Curve25519 public key of the peer. It must be
	// exactly 32 bytes.
	PublicKey []byte

	// AllowedIPs is the list of IP networks that will be routed to and accepted
	// from the peer.
	AllowedIPs []*net.IPNet

	// Endpoint is the network address that packets destined for the peer will
	// be sent to. If it is nil, packets destined for this peer will not be
	// routable until an incoming handshake is received.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval, if non-zero, is the number of seconds
	// between keep-alive packets sent to the peer.
	PersistentKeepaliveInterval int

	// LastHandshake is the timestamp of the last successful handshake with the
	// peer. This field is read-only.
	LastHandshake time.Time

	// RxBytes is the number of bytes received from the peer. This field is
	// read-only.
	RxBytes int64

	// TxBytes is the number of bytes transmitted to the peer. This field is
	// read-only.
	TxBytes int64
}

type peer struct {
	internalID uint64

	endpointAddr    *net.UDPAddr
	endpointAddrMtx sync.RWMutex

	handshake         noiseHandshake
	lastSentHandshake time.Time

	latestCookie cookie

	keypairs noiseKeypairs

	rxBytes, txBytes uint64

	txQueue chan []byte

	persistentKeepaliveInterval int
	needAnotherKeepalive        bool
	retransmitHandshake         *time.Timer
	sendKeepalive               *time.Timer
	newHandshake                *time.Timer
	killEphemerals              *time.Timer
	persistentKeepalive         *time.Timer

	iface *Interface
}

func (p *peer) public() *Peer {
	out := &Peer{
		Endpoint:      p.endpointAddr,
		LastHandshake: p.lastSentHandshake,
		RxBytes:       int64(p.rxBytes),
		TxBytes:       int64(p.txBytes),

		PersistentKeepaliveInterval: p.persistentKeepaliveInterval,
	}

	// This seems inefficient to fetch the public key of a peer
	// when it can be stored in the peer itself. Whatever.
	for k, v := range p.iface.peers {
		if v.internalID == p.internalID {
			out.PublicKey = k[:]
		}
	}

	return out
}

func (p *peer) updateLatestAddr(a *net.UDPAddr) {
	p.endpointAddrMtx.Lock()
	p.endpointAddr = a
	p.endpointAddrMtx.Unlock()
}

func (p *peer) rxStats(n int) {
	p.rxBytes += uint64(n)
}

func (p *peer) timerAnyAuthenticatedPacketReceived() {

}

func (p *peer) timerAnyAuthenticatedPacketTraversal() {

}

func (p *peer) timerEphemeralKeyCreated() {

}

func (p *peer) timerHandshakeComplete() {

}
