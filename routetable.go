package wireguard

import (
	"errors"
	"net"
	"sync"

	"github.com/flynn/go-wireguard/internal/critbitgo"
)

var (
	errInvalidIpPacket = errors.New("wireguard: invalid ip packet")
)

type RouteTable struct {
	trie *critbitgo.Net
	sync.RWMutex
}

// NewRouteTable creates a new routing table that handles both IPv4/IPv6 routes.
func NewRouteTable() RouteTable {
	return RouteTable{trie: critbitgo.NewNet()}
}

// Insert inserts the entry into the routing table. If a previous entry exists,
// it is replaced.
func (rt RouteTable) Insert(r *net.IPNet, p *peer) error {
	rt.Lock()
	defer rt.Unlock()
	return rt.trie.Add(r, p)
}

// Remove deletes the entry from the routing table.
func (rt RouteTable) Remove(r *net.IPNet) error {
	rt.Lock()
	defer rt.Unlock()
	_, _, err := rt.trie.Delete(r)
	return err
}

// Lookup returns the peer matching the longest prefix match
// for the given ip.
func (rt RouteTable) Lookup(ip net.IP) (p *peer, err error) {
	rt.RLock()
	defer rt.RUnlock()
	r, pInf, err := rt.trie.MatchIP(ip)
	if r == nil {
		p = nil
	} else {
		p = pInf.(*peer)
	}
	return p, err
}

func (rt RouteTable) LookupFromPacket(packet []byte) (p *peer, err error) {
	ipVer := packet[0] >> 4

	var dst net.IP

	if ipVer == 4 {
		dst = net.IP(packet[16:20])
	} else if ipVer == 6 {
		dst = net.IP(packet[24:40])
	} else {
		return nil, errInvalidIpPacket
	}

	return rt.Lookup(dst)
}

// RemoveByPeer deletes all entries associated with the given peer.
func (rt RouteTable) RemoveByPeer(p *peer) error {
	rt.Lock()
	defer rt.Unlock()
	routes := rt.trie.GetByValue(p)
	for _, r := range routes {
		_, _, err := rt.trie.Delete(r)
		if err != nil {
			return err
		}
	}
	return nil
}

// Clear sets the routing table to be empty.
func (rt RouteTable) Clear() {
	rt.Lock()
	rt.Unlock()
	rt.trie.Clear()
}
