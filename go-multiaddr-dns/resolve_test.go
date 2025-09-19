package madns

import (
	"context"
	"net"
	"strconv"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

var (
	ip4a = net.IPAddr{IP: net.ParseIP("192.0.2.1")}
	ip4b = net.IPAddr{IP: net.ParseIP("192.0.2.2")}
	ip6a = net.IPAddr{IP: net.ParseIP("2001:db8::a3")}
	ip6b = net.IPAddr{IP: net.ParseIP("2001:db8::a4")}
)

var (
	ip4ma, _ = ma.StringCast("/ip4/" + ip4a.IP.String())
	ip4mb, _ = ma.StringCast("/ip4/" + ip4b.IP.String())
	ip6ma, _ = ma.StringCast("/ip6/" + ip6a.IP.String())
	ip6mb, _ = ma.StringCast("/ip6/" + ip6b.IP.String())
)

var (
	mc, _ = ma.StringCast("/tcp/123/http")
	md, _ = ma.StringCast("/tcp/123")
	me, _ = ma.StringCast("/tcp/789/http")
	txtmc = ma.Join(ip4ma, mc)
	txtmd = ma.Join(ip4ma, md)
	txtme = ma.Join(ip4ma, me)
)

var (
	txta = "dnsaddr=" + ip4ma.String()
	txtb = "dnsaddr=" + ip6ma.String()
	txtc = "dnsaddr=" + txtmc.String()
	txtd = "dnsaddr=" + txtmd.String()
	txte = "dnsaddr=" + txtme.String()
)

func makeResolver() *Resolver {
	mock := &MockResolver{
		IP: map[string][]net.IPAddr{
			"example.com": {ip4a, ip4b, ip6a, ip6b},
		},
		TXT: map[string][]string{
			"_dnsaddr.example.com":  {txta, txtb},
			"_dnsaddr.matching.com": {txtc, txtd, txte, "not a dnsaddr", "dnsaddr=/foobar"},
		},
	}
	resolver := &Resolver{def: mock}
	return resolver
}

func TestMatches(t *testing.T) {
	a, _ := ma.StringCast("/tcp/1234/dns6/example.com")
	if !Matches(a) {
		// Pretend this is a p2p-circuit address. Unfortunately, we'd
		// need to depend on the circuit package to parse it.
		t.Fatalf("expected match, didn't: /tcp/1234/dns6/example.com")
	}
	b, _ := ma.StringCast("/dns/example.com")
	if !Matches(b) {
		t.Fatalf("expected match, didn't: /dns/example.com")
	}
	c, _ := ma.StringCast("/dns4/example.com")
	if !Matches(c) {
		t.Fatalf("expected match, didn't: /dns4/example.com")
	}
	d, _ := ma.StringCast("/dns6/example.com")
	if !Matches(d) {
		t.Fatalf("expected match, didn't: /dns6/example.com")
	}
	e, _ := ma.StringCast("/dnsaddr/example.com")
	if !Matches(e) {
		t.Fatalf("expected match, didn't: /dnsaddr/example.com")
	}
	if Matches(ip4ma) {
		t.Fatalf("expected no-match, but did: %s", ip4ma.String())
	}
}

func TestSimpleIPResolve(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/dns4/example.com")
	b, _ := ma.StringCast("/dns6/example.com")
	c, _ := ma.StringCast("/dns/example.com")
	addrs4, err := resolver.Resolve(ctx, a)
	if err != nil {
		t.Error(err)
	}
	if len(addrs4) != 2 || !addrs4[0].Equal(ip4ma) || addrs4[0].Equal(ip4mb) {
		t.Fatalf("expected [%s %s], got %+v", ip4ma, ip4mb, addrs4)
	}

	addrs6, err := resolver.Resolve(ctx, b)
	if err != nil {
		t.Error(err)
	}
	if len(addrs6) != 2 || !addrs6[0].Equal(ip6ma) || addrs6[0].Equal(ip6mb) {
		t.Fatalf("expected [%s %s], got %+v", ip6ma, ip6mb, addrs6)
	}

	addrs, err := resolver.Resolve(ctx, c)
	if err != nil {
		t.Error(err)
	}
	for i, expected := range []ma.Multiaddr{ip4ma, ip4mb, ip6ma, ip6mb} {
		if !expected.Equal(addrs[i]) {
			t.Fatalf("%d: expected %s, got %s", i, expected, addrs[i])
		}
	}
}

func TestResolveOnlyOnce(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/dns4/example.com/quic/dns6/example.com")
	addrs, err := resolver.Resolve(ctx, a)
	if err != nil {
		t.Error(err)
	}

	for i, x := range []ma.Multiaddr{ip4ma, ip4mb} {
		b, _ := ma.StringCast("/quic/dns6/example.com")
		expected := ma.Join(x, b)
		actual := addrs[i]
		if !expected.Equal(actual) {
			t.Fatalf("expected %s, got %s", expected, actual)
		}
	}
}

func resolveAllDNS(ctx context.Context, resolver *Resolver, in ma.Multiaddr) ([]ma.Multiaddr, error) {
	if !Matches(in) {
		return []ma.Multiaddr{in}, nil
	}
	var outAddrs []ma.Multiaddr
	toResolve := []ma.Multiaddr{in}

	for len(toResolve) > 0 {
		var nextToResolve []ma.Multiaddr
		for _, a := range toResolve {
			addrs, err := resolver.Resolve(ctx, a)
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				if Matches(addr) {
					nextToResolve = append(nextToResolve, addr)
				} else {
					outAddrs = append(outAddrs, addr)
				}
			}
		}
		toResolve = nextToResolve
	}
	return outAddrs, nil
}

func TestResolveMultiple(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/dns4/example.com/quic/dns6/example.com")
	addrs, err := resolveAllDNS(ctx, resolver, a)
	if err != nil {
		t.Error(err)
	}
	for i, x := range []ma.Multiaddr{ip4ma, ip4mb} {
		for j, y := range []ma.Multiaddr{ip6ma, ip6mb} {
			b, _ := ma.StringCast("/quic")
			expected := ma.Join(x, b, y)
			actual := addrs[i*2+j]
			if !expected.Equal(actual) {
				t.Fatalf("expected %s, got %s", expected, actual)
			}
		}
	}
}

func TestResolveMultipleSandwitch(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/quic/dns4/example.com/dns6/example.com/http")
	addrs, err := resolveAllDNS(ctx, resolver, a)
	if err != nil {
		t.Error(err)
	}
	for i, x := range []ma.Multiaddr{ip4ma, ip4mb} {
		for j, y := range []ma.Multiaddr{ip6ma, ip6mb} {
			a, _ := ma.StringCast("/quic")
			b, _ := ma.StringCast("/http")
			expected := ma.Join(a, x, y, b)
			actual := addrs[i*2+j]
			if !expected.Equal(actual) {
				t.Fatalf("expected %s, got %s", expected, actual)
			}
		}
	}
}

func TestSimpleTXTResolve(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/dnsaddr/example.com")
	addrs, err := resolver.Resolve(ctx, a)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) != 2 || !addrs[0].Equal(ip4ma) || addrs[0].Equal(ip6ma) {
		t.Fatalf("expected [%s %s], got %+v", ip4ma, ip6ma, addrs)
	}
}

func TestNonResolvable(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	addrs, err := resolver.Resolve(ctx, ip4ma)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) != 1 || !addrs[0].Equal(ip4ma) {
		t.Fatalf("expected [%s], got %+v", ip4ma, addrs)
	}
}

func TestLongMatch(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/dnsaddr/example.com/quic/quic/quic/quic")
	res, err := resolver.Resolve(ctx, a)
	if err != nil {
		t.Error(err)
	}
	if len(res) != 0 {
		t.Error("expected no results")
	}
}

func TestEmptyResult(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/dnsaddr/none.com")
	addrs, err := resolver.Resolve(ctx, a)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) > 0 {
		t.Fatalf("expected [], got %+v", addrs)
	}
}

func TestNil(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	addrs, err := resolver.Resolve(ctx, nil)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) > 0 {
		t.Fatalf("expected [], got %+v", addrs)
	}
}

func TestDnsaddrMatching(t *testing.T) {
	ctx := context.Background()
	resolver := makeResolver()

	a, _ := ma.StringCast("/dnsaddr/matching.com/tcp/123/http")
	addrs, err := resolver.Resolve(ctx, a)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) != 1 || !addrs[0].Equal(txtmc) {
		t.Fatalf("expected [%s], got %+v", txtmc, addrs)
	}

	a, _ = ma.StringCast("/dnsaddr/matching.com/tcp/123")
	addrs, err = resolver.Resolve(ctx, a)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) != 1 || !addrs[0].Equal(txtmd) {
		t.Fatalf("expected [%s], got %+v", txtmd, addrs)
	}
}

func TestBadDomain(t *testing.T) {
	bt, _ := ma.StringCast("/dns4/example.com")
	bts := bt.Bytes()
	bts[len(bts)-5] = '/'
	_, err := ma.NewMultiaddrBytes(bts)
	if err == nil {
		t.Error("expected malformed address to fail to parse")
	}
}

func TestCustomResolver(t *testing.T) {
	ip1 := net.IPAddr{IP: net.ParseIP("1.2.3.4")}
	ip2 := net.IPAddr{IP: net.ParseIP("2.3.4.5")}
	ip3 := net.IPAddr{IP: net.ParseIP("3.4.5.6")}
	ip4 := net.IPAddr{IP: net.ParseIP("4.5.6.8")}
	ip5 := net.IPAddr{IP: net.ParseIP("5.6.8.9")}
	ip6 := net.IPAddr{IP: net.ParseIP("6.8.9.10")}
	def := &MockResolver{
		IP: map[string][]net.IPAddr{
			"example.com": {ip1},
		},
	}
	custom1 := &MockResolver{
		IP: map[string][]net.IPAddr{
			"custom.test":         {ip2},
			"another.custom.test": {ip3},
			"more.custom.test":    {ip6},
		},
	}
	custom2 := &MockResolver{
		IP: map[string][]net.IPAddr{
			"more.custom.test":      {ip4},
			"some.more.custom.test": {ip5},
		},
	}

	rslv, err := NewResolver(
		WithDefaultResolver(def),
		WithDomainResolver("custom.test", custom1),
		WithDomainResolver("more.custom.test", custom2),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	res, err := rslv.LookupIPAddr(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 1 || !res[0].IP.Equal(ip1.IP) {
		t.Fatal("expected result to be ip1")
	}

	res, err = rslv.LookupIPAddr(ctx, "custom.test")
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 1 || !res[0].IP.Equal(ip2.IP) {
		t.Fatal("expected result to be ip2")
	}

	res, err = rslv.LookupIPAddr(ctx, "another.custom.test")
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 1 || !res[0].IP.Equal(ip3.IP) {
		t.Fatal("expected result to be ip3")
	}

	res, err = rslv.LookupIPAddr(ctx, "more.custom.test")
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 1 || !res[0].IP.Equal(ip4.IP) {
		t.Fatal("expected result to be ip4")
	}

	res, err = rslv.LookupIPAddr(ctx, "some.more.custom.test")
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 1 || !res[0].IP.Equal(ip5.IP) {
		t.Fatal("expected result to be ip5")
	}
}

func TestLimitResolver(t *testing.T) {
	var ipaddrs []net.IPAddr
	for i := 0; i < 255; i++ {
		ipaddrs = append(ipaddrs, net.IPAddr{IP: net.ParseIP("1.2.3." + strconv.Itoa(i))})
	}

	mock := &MockResolver{
		IP: map[string][]net.IPAddr{
			"example.com": ipaddrs,
		},
		TXT: map[string][]string{},
	}
	resolver := &Resolver{def: mock}

	a, _ := ma.StringCast("/dns4/example.com")
	addrs, err := resolver.Resolve(context.Background(), a)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) != maxResolvedAddrs {
		t.Fatalf("expected %d, got %d", maxResolvedAddrs, len(addrs))
	}
}
