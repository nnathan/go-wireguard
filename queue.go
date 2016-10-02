package wireguard

// PacketQueue is a FIFO queue backed by a single linked list.

import "sync"

type PacketQueue struct {
	head, tail *node
	len        int
	sync.RWMutex
}

type node struct {
	value []byte
	next  *node
}

func (pq *PacketQueue) BoundedAppend(v []byte, maxSize int) {
	pq.Lock()
	defer pq.Unlock()

	if maxSize > 0 {
		for pq.len > maxSize {
			pq.Pop()
		}
	}

	n := &node{value: v}

	if pq.len > 0 {
		pq.tail.next = n
		pq.tail = n
	} else {
		pq.head = n
		pq.tail = n
	}

	pq.len++
}

func (pq *PacketQueue) Append(v []byte) {
	pq.Lock()
	defer pq.Unlock()

	n := &node{value: v}

	if pq.len > 0 {
		pq.tail.next = n
		pq.tail = n
	} else {
		pq.head = n
		pq.tail = n
	}

	pq.len++
}

func (pq *PacketQueue) Pop() (v []byte) {
	pq.Lock()
	defer pq.Unlock()

	v = nil

	if pq.len > 0 {
		v = pq.head.value
		pq.len--
		pq.head = pq.head.next
		if pq.len == 0 {
			pq.tail = nil
		}
	}

	return v
}

func (pq *PacketQueue) Peek() []byte {
	pq.RLock()
	defer pq.RUnlock()

	if pq.len == 0 {
		return nil
	}

	return pq.head.value
}
func (pq *PacketQueue) Len() int {
	pq.RLock()
	defer pq.RUnlock()
	return pq.len
}

func (pq *PacketQueue) Steal() *PacketQueue {
	pq.Lock()
	defer pq.Unlock()
	newq := &PacketQueue{head: pq.head, tail: pq.tail, len: pq.len}
	pq.len = 0
	pq.head = nil
	pq.tail = nil
	return newq
}
