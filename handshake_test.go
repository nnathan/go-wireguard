package wireguard

import (
	"testing"
)

func TestNoiseCounterValidate(t *testing.T) {
	const lim = CounterWindowSize + 1
	c := noiseCounter{backtrack: new([CounterBitsTotal / BitsPerInt]uint)}
	reset := func() {
		c.counter = 0
		for i := range c.backtrack {
			c.backtrack[i] = 0
		}
	}

	id := 1

	try := func(n uint64, expected bool) {
		if c.Validate(n) != expected {
			t.Errorf("nonce counter test %d: FAIL", id)
		}
		id++
	}

	reset()
	for _, tt := range []struct {
		n uint64
		v bool
	}{
		/* 1  */ {0, true},
		/* 2  */ {1, true},
		/* 3  */ {1, false},
		/* 4  */ {9, true},
		/* 5  */ {8, true},
		/* 6  */ {7, true},
		/* 7  */ {7, false},
		/* 8  */ {lim, true},
		/* 9  */ {lim - 1, true},
		/* 10 */ {lim - 1, false},
		/* 11 */ {lim - 2, true},
		/* 12 */ {2, true},
		/* 13 */ {2, false},
		/* 14 */ {lim + 16, true},
		/* 15 */ {3, false},
		/* 16 */ {lim + 16, false},
		/* 17 */ {lim * 4, true},
		/* 18 */ {lim*4 - (lim - 1), true},
		/* 19 */ {10, false},
		/* 20 */ {lim*4 - lim, false},
		/* 21 */ {lim*4 - (lim + 1), false},
		/* 22 */ {lim*4 - (lim - 2), true},
		/* 23 */ {lim*4 + 1 - lim, false},
		/* 24 */ {0, false},
		/* 25 */ {RejectAfterMessages, false},
		/* 26 */ {RejectAfterMessages - 1, true},
		/* 27 */ {RejectAfterMessages, false},
		/* 28 */ {RejectAfterMessages - 1, false},
		/* 29 */ {RejectAfterMessages - 2, true},
		/* 30 */ {RejectAfterMessages + 1, false},
		/* 31 */ {RejectAfterMessages + 2, false},
		/* 32 */ {RejectAfterMessages - 2, false},
		/* 33 */ {RejectAfterMessages - 3, true},
		/* 34 */ {0, false},
	} {
		try(tt.n, tt.v)
	}

	reset()

	/* 35 */
	for i := 1; i <= CounterWindowSize; i++ {
		try(uint64(i), true)
	}
	/* 2019 */
	try(0, true)
	try(0, false)

	/* 2021 */
	reset()
	for i := 2; i <= CounterWindowSize+1; i++ {
		try(uint64(i), true)
	}
	/* 4006 */
	try(1, true)
	try(0, false)

	/* 4008 */
	reset()
	for i := CounterWindowSize + 1; (i - 1) > 0; {
		i--
		try(uint64(i), true)
	}

	/* 5992 */
	reset()
	for i := CounterWindowSize + 2; i > 1; {
		i--
		try(uint64(i), true)
	}
	/* 7997 */
	try(0, false)

	/* 7998 */
	reset()
	for i := CounterWindowSize + 1; i > 1; {
		i--
		try(uint64(i), true)
	}
	/* 9962 */
	try(CounterWindowSize+1, true)
	try(0, false)

	/* 9964 */
	reset()
	for i := CounterWindowSize + 1; i > 1; {
		i--
		try(uint64(i), true)
	}

	/* 11948 */
	try(0, true)
	try(CounterWindowSize+1, true)
}
