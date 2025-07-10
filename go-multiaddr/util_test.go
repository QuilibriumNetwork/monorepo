package multiaddr

import (
	"strings"
	"testing"
)

func TestSplitFirstLast(t *testing.T) {
	ipStr := "/ip4/0.0.0.0"
	tcpStr := "/tcp/123"
	quicStr := "/quic"
	ipfsStr := "/ipfs/QmPSQnBKM9g7BaUcZCvswUJVscQ1ipjmwxN5PXCjkp9EQ7"

	for _, x := range [][]string{
		{ipStr, tcpStr, quicStr, ipfsStr},
		{ipStr, tcpStr, ipfsStr},
		{ipStr, tcpStr},
		{ipStr},
	} {
		addr, _ := StringCast(strings.Join(x, ""))
		head, tail := SplitFirst(addr)
		rest, last := SplitLast(addr)
		if len(x) == 0 {
			if head != nil {
				t.Error("expected head to be nil")
			}
			if tail != nil {
				t.Error("expected tail to be nil")
			}
			if rest != nil {
				t.Error("expected rest to be nil")
			}
			if last != nil {
				t.Error("expected last to be nil")
			}
			continue
		}
		s, _ := StringCast(x[0])
		if !head.Multiaddr().Equal(s) {
			t.Errorf("expected %s to be %s", head, x[0])
		}
		s, _ = StringCast(x[len(x)-1])
		if !last.Multiaddr().Equal(s) {
			t.Errorf("expected %s to be %s", head, x[len(x)-1])
		}
		if len(x) == 1 {
			if tail != nil {
				t.Error("expected tail to be nil")
			}
			if rest != nil {
				t.Error("expected rest to be nil")
			}
			continue
		}
		tailExp := strings.Join(x[1:], "")
		s, _ = StringCast(tailExp)
		if !tail.Equal(s) {
			t.Errorf("expected %s to be %s", tail, tailExp)
		}
		restExp := strings.Join(x[:len(x)-1], "")
		s, _ = StringCast(restExp)
		if !rest.Equal(s) {
			t.Errorf("expected %s to be %s", rest, restExp)
		}
	}

	c, err := NewComponent("ip4", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	ci, m := SplitFirst(c.Multiaddr())
	if !ci.Equal(c) || m != nil {
		t.Error("split first on component failed")
	}
	m, ci = SplitLast(c.Multiaddr())
	if !ci.Equal(c) || m != nil {
		t.Error("split last on component failed")
	}
	cis := Split(c.Multiaddr())
	if len(cis) != 1 || !cis[0].Equal(c) {
		t.Error("split on component failed")
	}
	m1, m2 := SplitFunc(c.Multiaddr(), func(c Component) bool {
		return true
	})
	if m1 != nil || !m2.Equal(c.Multiaddr()) {
		t.Error("split func(true) on component failed")
	}
	m1, m2 = SplitFunc(c.Multiaddr(), func(c Component) bool {
		return false
	})
	if !m1.Equal(c.Multiaddr()) || m2 != nil {
		t.Error("split func(false) on component failed")
	}

	i := 0
	ForEach(c.Multiaddr(), func(ci Component, e error) bool {
		if e != nil {
			t.Error(e)
		}
		if i != 0 {
			t.Error("expected exactly one component")
		}
		i++
		if !ci.Equal(c) {
			t.Error("foreach on component failed")
		}
		return true
	})
}

func TestSplitFunc(t *testing.T) {
	ipStr := "/ip4/0.0.0.0"
	tcpStr := "/tcp/123"
	quicStr := "/quic"
	ipfsStr := "/ipfs/QmPSQnBKM9g7BaUcZCvswUJVscQ1ipjmwxN5PXCjkp9EQ7"

	for _, x := range [][]string{
		{ipStr, tcpStr, quicStr, ipfsStr},
		{ipStr, tcpStr, ipfsStr},
		{ipStr, tcpStr},
		{ipStr},
	} {
		addr, _ := StringCast(strings.Join(x, ""))
		for i, cs := range x {
			target, _ := StringCast(cs)
			a, b := SplitFunc(addr, func(c Component) bool {
				return c.Multiaddr().Equal(target)
			})
			if i == 0 {
				if a != nil {
					t.Error("expected nil addr")
				}
			} else {
				s, _ := StringCast(strings.Join(x[:i], ""))
				if !a.Equal(s) {
					t.Error("split failed")
				}
				s, _ = StringCast(strings.Join(x[i:], ""))
				if !b.Equal(s) {
					t.Error("split failed")
				}
			}
		}
		a, b := SplitFunc(addr, func(_ Component) bool { return false })
		if !a.Equal(addr) || b != nil {
			t.Error("should not have split")
		}
	}
}
