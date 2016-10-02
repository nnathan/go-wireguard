package wireguard

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

var (
	errPeerDoesntExist = errors.New("wireguard: peer doesnt exist")
)

const maxQueuePackets int = 1024

// An InterfaceConfig is the configuration used to create an interface.
type InterfaceConfig struct {
	// Outside is the connection that will be used to send and receive encrypted
	// packets with peers. It will be closed if Close is called on the Interface.
	Outside UDPConn

	// Inside is the interface that will be used to read plaintext packets
	// destined for peers and write decrypted packets received from peers. Each
	// Read must return a single IP packet to send to a peer, and each Write
	// will provide a single received IP packet.
	Inside io.ReadWriter

	// PrivateKey holds the static Curve25519 private key for the interface. If
	// set, it must be exactly 32 random bytes.
	PrivateKey []byte

	// PresharedKey holds an optional pre-shared key to use during handshakes.
	// If set, it must be exactly 32 random bytes.
	PresharedKey []byte

	// Peers is the initial set of peers that the interface will communicate
	// with.
	Peers []*Peer
}

func NewInterface(c InterfaceConfig) (*Interface, error) {
	if c.Outside == nil {
		return nil, errors.New("wireguard: Outside connection is nil")
	}
	if c.Inside == nil {
		return nil, errors.New("wireguard: Inside pipe is nil")
	}

	f := &Interface{
		outside: c.Outside,
		inside:  c.Inside,
	}

	if err := f.SetPrivateKey(c.PrivateKey); err != nil {
		return nil, err
	}
	if err := f.SetPresharedKey(c.PresharedKey); err != nil {
		return nil, err
	}

	f.handshakes = make(map[uint32]*noiseHandshake)

	f.routetable = NewRouteTable()

	if err := f.SetPeers(c.Peers); err != nil {
		return nil, err
	}

	return f, nil
}

type publicKey [32]byte

// An Interface communicates encrypted packets with peers.
type Interface struct {
	started bool

	outside UDPConn
	inside  io.ReadWriter

	identityMtx  sync.RWMutex // protects staticKey and presharedKey
	staticKey    noise.DHKey
	presharedKey []byte

	peersMtx sync.RWMutex
	peers    map[publicKey]*peer
	peerList []*peer

	handshakesMtx sync.RWMutex
	handshakes    map[uint32]*noiseHandshake

	keypairsMtx sync.RWMutex
	keypairs    map[uint32]*noiseKeypair

	routetable RouteTable
}

// Run starts the interface and blocks until it is closed.
func (f *Interface) Run() error {
	if f.started {
		return errors.New("wireguard: the interface is already started")
	}

	// What do we do here?
	// 1. Watch for incoming packets from listening UDP connection
	// 2. Watch for incoming packets from inside interface (io.ReadWriter)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		// udp socket read loop
		f.acceptOutsidePackets()
		wg.Done()
	}()

	go func() {
		// handle inside interface i/o
		f.readInsidePackets()
		wg.Done()
	}()

	wg.Wait()

	return nil
}

// Close shuts down the interface.
func (f *Interface) Close() error {
	return f.outside.Close()
}

// SetPrivateKey changes the private key for the interface. It is safe to call
// while the interface is running.
func (f *Interface) SetPrivateKey(k []byte) error {
	if len(k) != 0 && len(k) != 32 {
		return errors.New("wireguard: PrivateKey must be exactly 32 bytes")
	}

	f.identityMtx.Lock()
	defer f.identityMtx.Unlock()

	if len(k) == 0 {
		f.staticKey.Private = nil
		f.staticKey.Public = nil
		return nil
	}

	// calculate public key and set the keys on the interface
	var pubkey, privkey [32]byte
	copy(privkey[:], k)
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	f.staticKey.Private = privkey[:]
	f.staticKey.Public = pubkey[:]

	return nil
}

// SetPresharedKey changes the pre-shared key for the interface.
func (f *Interface) SetPresharedKey(k []byte) error {
	if len(k) != 0 && len(k) != 32 {
		return errors.New("wireguard: PresharedKey must be exactly 32 bytes")
	}

	f.identityMtx.Lock()
	defer f.identityMtx.Unlock()

	if len(k) == 0 {
		f.presharedKey = nil
	} else {
		key := make([]byte, 32)
		copy(key, k)
		f.presharedKey = key
	}

	return nil
}

// SetPeers replaces all of the peers that the interface is configured for with
// a new list.
func (f *Interface) SetPeers(peers []*Peer) error {
	f.routetable.Clear()
	f.peersMtx.Lock()
	f.peerList = []*peer{}
	f.peers = make(map[publicKey]*peer)
	f.peersMtx.Unlock()

	for _, p := range peers {
		if err := f.AddPeer(p); err != nil {
			return err
		}
	}

	return nil
}

// GetPeers retrieves a list of all peers known to the interface.
func (f *Interface) GetPeers() []*Peer {
	peers := make([]*Peer, len(f.peerList))

	for i, v := range f.peerList {
		peers[i] = v.public()
	}

	return peers
}

// RemovePeer removes the peer identified with the public key pubkey from the
// interface configuration.
func (f *Interface) RemovePeer(pubkey []byte) error {
	pk := publicKey{}
	copy(pk[:], pubkey)
	p := f.peers[pk]

	if p == nil {
		return errPeerDoesntExist
	}

	f.peersMtx.Lock()
	for i := range f.peerList {
		if p.internalID == f.peerList[i].internalID {
			copy(f.peerList[i:], f.peerList[i+1:])
			break
		}
	}
	f.peersMtx.Unlock()

	p.handshake.clear()
	p.keypairs.clear()

	err := f.routetable.RemoveByPeer(p)

	f.peersMtx.Lock()
	delete(f.peers, pk)
	f.peersMtx.Unlock()

	p.retransmitHandshake.Stop()
	p.sendKeepalive.Stop()
	p.newHandshake.Stop()
	p.killEphemerals.Stop()
	p.persistentKeepalive.Stop()
	p.txQueue = nil

	return err
}

// AddPeer adds a peer to the interface configuration. If the peer, identified
// by its public key, already exists, then all configuration will be replaced
// with the new fields.
func (f *Interface) AddPeer(p *Peer) error {
	pk := publicKey{}
	copy(pk[:], p.PublicKey)

	np := f.peers[pk]

	// peer exists
	if np != nil {
		_ = f.routetable.RemoveByPeer(np)
		goto ReplaceExistingPeer
	}

	// new peer
	np = &peer{internalID: atomic.AddUint64(&peerCounter, 1)}
	f.peersMtx.Lock()
	f.peers[pk] = np
	f.peerList = append(f.peerList, np)
	f.peersMtx.Unlock()
	np.txQueue = &PacketQueue{}
	np.handshake = noiseHandshake{remoteStatic: [32]byte(pk), peer: np}
	np.iface = f
	np.initTimers()

ReplaceExistingPeer:

	np.persistentKeepaliveInterval = p.PersistentKeepaliveInterval

	np.endpointAddrMtx.Lock()
	np.endpointAddr = p.Endpoint
	fmt.Println("adding peer: ", np.endpointAddr)
	if np.endpointAddr != nil {
		np.conn = f.outside
	}
	np.endpointAddrMtx.Unlock()

	for _, r := range p.AllowedIPs {
		if err := f.routetable.Insert(r, np); err != nil {
			defer f.routetable.RemoveByPeer(np)
			return err
		}
	}

	return nil
}
