package critbitgo_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/flynn/go-wireguard/internal/critbitgo"
)

func buildTrie(t *testing.T, keys []string) *critbitgo.Trie {
	trie := critbitgo.NewTrie()
	for _, key := range keys {
		if !trie.Insert([]byte(key), key) {
			t.Errorf("Insert() - failed insert \"%s\"\n%s", key, dumpTrie(trie))
		}
	}
	return trie
}

func dumpTrie(trie *critbitgo.Trie) string {
	buf := bytes.NewBufferString("")
	trie.Dump(buf)
	return buf.String()
}

func TestInsert(t *testing.T) {
	// normal build
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	trie := buildTrie(t, keys)
	dump := dumpTrie(trie)

	// random build
	random := rand.New(rand.NewSource(0))
	for i := 0; i < 10; i++ {
		// shuffle keys
		lkeys := make([]string, len(keys))
		for j, index := range random.Perm(len(keys)) {
			lkeys[j] = keys[index]
		}

		ltrie := buildTrie(t, lkeys)
		ldump := dumpTrie(ltrie)
		if dump != ldump {
			t.Errorf("Insert() - different tries\norigin:\n%s\nother:\n%s\n", dump, ldump)
		}
	}

	// error check
	if trie.Insert([]byte("a"), nil) {
		t.Error("Insert() - check exists")
	}
	if !trie.Insert([]byte("c"), nil) {
		t.Error("Insert() - check not exists")
	}
}

func TestSet(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	trie := buildTrie(t, keys)

	trie.Set([]byte("a"), 100)
	v, _ := trie.Get([]byte("a"))
	if n, ok := v.(int); !ok || n != 100 {
		t.Errorf("Set() - failed replace - %v", v)
	}
}

func TestContains(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	trie := buildTrie(t, keys)

	for _, key := range keys {
		if !trie.Contains([]byte(key)) {
			t.Error("Contains() - not found - %s", key)
		}
	}

	if trie.Contains([]byte("aaa")) {
		t.Error("Contains() - phantom found")
	}
}

func TestGet(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	trie := buildTrie(t, keys)

	for _, key := range keys {
		if value, ok := trie.Get([]byte(key)); value != key || !ok {
			t.Error("Get() - not found - %s", key)
		}
	}

	if value, ok := trie.Get([]byte("aaa")); value != nil || ok {
		t.Error("Get() - phantom found")
	}
}

func TestDelete(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	trie := buildTrie(t, keys)

	for i, key := range keys {
		if !trie.Contains([]byte(key)) {
			t.Error("Delete() - not exists - %s", key)
		}
		if v, ok := trie.Delete([]byte(key)); !ok || v != key {
			t.Error("Delete() - failed - %s", key)
		}
		if trie.Contains([]byte(key)) {
			t.Error("Delete() - exists - %s", key)
		}
		if i != len(keys) {
			for _, key2 := range keys[i+1:] {
				if !trie.Contains([]byte(key2)) {
					t.Errorf("Delete() - other not exists - %s", key2)
				}
			}
		}
	}
}

func TestSize(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	trie := buildTrie(t, keys)
	klen := len(keys)
	if s := trie.Size(); s != klen {
		t.Errorf("Size() - expected [%s], actual [%s]", klen, s)
	}

	for i, key := range keys {
		trie.Delete([]byte(key))
		if s := trie.Size(); s != klen-(i+1) {
			t.Errorf("Size() - expected [%s], actual [%s]", klen, s)
		}
	}
}

func TestAllprefixed(t *testing.T) {
	keys := []string{"", "a", "aa", "b", "bb", "ab", "ba", "aba", "bab"}
	trie := buildTrie(t, keys)

	elems := make(map[string]interface{})
	handle := func(key []byte, value interface{}) bool {
		elems[string(key)] = value
		return true
	}
	if !trie.Allprefixed([]byte(""), handle) {
		t.Error("Allprefixed() - invalid result")
	}
	for _, key := range keys {
		if _, ok := elems[key]; !ok {
			t.Errorf("Allprefixed() - not found [%s]", key)
		}
	}

	elems = make(map[string]interface{})
	if !trie.Allprefixed([]byte("a"), handle) {
		t.Error("Allprefixed() - invalid result")
	}
	for _, key := range []string{"a", "aa", "ab", "aba"} {
		if _, ok := elems[key]; !ok {
			t.Errorf("Allprefixed() - not found [%s]", key)
		}
	}

	elems = make(map[string]interface{})
	handle = func(key []byte, value interface{}) bool {
		elems[string(key)] = value
		if string(key) == "aa" {
			return false
		}
		return true
	}
	if trie.Allprefixed([]byte("a"), handle) {
		t.Error("Allprefixed() - invalid result")
	}
	for _, key := range []string{"a", "aa"} {
		if _, ok := elems[key]; !ok {
			t.Errorf("Allprefixed() - not found [%s]", key)
		}
	}
	for _, key := range []string{"ab", "aba"} {
		if _, ok := elems[key]; ok {
			t.Errorf("Allprefixed() - phantom found [%s]", key)
		}
	}
}

func TestKeyContainsZeroValue(t *testing.T) {
	trie := critbitgo.NewTrie()
	trie.Insert([]byte{1, 0, 1}, nil)
	trie.Insert([]byte{1}, nil)
	trie.Insert([]byte{0, 1, 1}, nil)
	trie.Insert([]byte{}, nil)
	trie.Insert([]byte{0, 0, 1}, nil)
	trie.Insert([]byte{1, 1}, nil)
	trie.Insert([]byte{1, 1, 1}, nil)
	trie.Insert([]byte{0, 1}, nil)
	trie.Insert([]byte{0, 1, 0}, nil)
	trie.Insert([]byte{0, 0}, nil)
	trie.Insert([]byte{0, 0, 0}, nil)
	trie.Insert([]byte{0}, nil)

	var index int
	exp := [][]byte{
		[]byte{},
		[]byte{0},
		[]byte{0, 0},
		[]byte{0, 0, 0},
		[]byte{0, 0, 1},
		[]byte{0, 1},
		[]byte{0, 1, 0},
		[]byte{0, 1, 1},
		[]byte{1},
		[]byte{1, 0, 1},
		[]byte{1, 1},
		[]byte{1, 1, 1},
	}
	handle := func(key []byte, _ interface{}) bool {
		if !bytes.Equal(exp[index], key) {
			t.Errorf("Key Order - index=%d, expected [%x], actula [%x]", index, exp[index], key)
		}
		index += 1
		return true
	}
	trie.Allprefixed([]byte(""), handle)
}
