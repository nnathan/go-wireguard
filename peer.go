package wireguard

import (
	"fmt"
	"log"
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
	conn            UDPConn

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

	p.iface.routetable.RLock()
	routes := p.iface.routetable.trie.GetByValue(p)
	p.iface.routetable.RUnlock()

	pubkey := []byte{}
	// This seems inefficient to fetch the public key of a peer
	// when it can be stored in the peer itself. Whatever.
	p.iface.peersMtx.RLock()
	for k, v := range p.iface.peers {
		if v.internalID == p.internalID {
			pubkey = k[:]
		}
	}
	p.iface.peersMtx.RUnlock()

	out := &Peer{
		Endpoint:                    p.endpointAddr,
		LastHandshake:               p.lastSentHandshake,
		RxBytes:                     int64(p.rxBytes),
		TxBytes:                     int64(p.txBytes),
		AllowedIPs:                  routes,
		PublicKey:                   pubkey,
		PersistentKeepaliveInterval: p.persistentKeepaliveInterval,
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

func (p *peer) txStats(n int) {
	p.txBytes += uint64(n)
}

func (p *peer) send(packet []byte) error {

	// we drop old packets from txQueue to insert new packets,
	// however we need to wrap this in a for loop since we
	// contend with multiple goroutines
queueLoop:
	for {
		select {
		case p.txQueue <- packet:
			// inserted in queue, we're good
			break queueLoop
		default:
			// queue full, remove from tail
			<-p.txQueue
		}
	}

	p.keypairs.RLock()
	var hs []byte
	defer p.keypairs.RUnlock()
	if p.keypairs.current == nil {
		// no keypair exist, need to fire up a job to initiate noise handshake
		if p.handshake.state == handshakeStateZeroed {
			hs = p.iface.handshakeCreateInitiation(&p.handshake)
			hs = p.iface.cookieAddMACs(hs, p)
			p.timerAnyAuthenticatedPacketTraversal()
			n, err := p.conn.WriteToUDP(hs, p.endpointAddr)
			p.timerHandshakeInitiated()
			p.txStats(n)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *peer) initTimers() {
	// since timers immediately begin after creation we use time.Hour
	// to give ample time to stop them
	p.retransmitHandshake = time.AfterFunc(time.Hour, p.expiredRetransmitHandshake)
	p.retransmitHandshake.Stop()
	p.sendKeepalive = time.AfterFunc(time.Hour, p.expiredSendKeepalive)
	p.sendKeepalive.Stop()
	p.newHandshake = time.AfterFunc(time.Hour, p.expiredNewHandshake)
	p.newHandshake.Stop()
	p.killEphemerals = time.AfterFunc(time.Hour, p.expiredKillEphemerals)
	p.killEphemerals.Stop()
	p.persistentKeepalive = time.AfterFunc(time.Hour, p.expiredPersistentKeepalive)
	p.persistentKeepalive.Stop()

}

func (p *peer) timerHandshakeInitiated() {
}

func (p *peer) timerAnyAuthenticatedPacketReceived() {

}

func (p *peer) timerAnyAuthenticatedPacketTraversal() {
	if p.persistentKeepaliveInterval > 0 {
		if !p.persistentKeepalive.Stop() {
			<-p.persistentKeepalive.C
		}
		p.persistentKeepalive.Reset(slackTime(p.persistentKeepaliveInterval))
	}
}

func (p *peer) timerEphemeralKeyCreated() {

}

func (p *peer) timerHandshakeComplete() {

}

func (p *peer) expiredRetransmitHandshake() {}
func (p *peer) expiredSendKeepalive()       {}
func (p *peer) expiredNewHandshake()        {}
func (p *peer) expiredKillEphemerals()      {}

func (p *peer) expiredPersistentKeepalive() {
	if p.persistentKeepaliveInterval == 0 {
		return
	}

	// TODO: only print in debug mode
	log.Printf("Sending keep alive packet to peer %s, since we haven't sent or received authenticated data for %d seconds", p, p.persistentKeepaliveInterval)

	// TODO: construct and send keepalive packet
}

func (p *peer) String() string {
	return fmt.Sprintf("%d (%s:%d)", p.internalID, p.endpointAddr.IP, p.endpointAddr.Port)
}
func slackTime(seconds int) time.Duration {
	const quarterSecond = 250 * time.Millisecond
	return time.Duration(seconds)*time.Second - quarterSecond
}
