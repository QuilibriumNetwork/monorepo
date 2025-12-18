package p2p

import (
	"net/netip"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
)

func Test_categorizeMultiaddrs(t *testing.T) {
	publicMaddrStrs := []string{
		"/ip4/17.3.2.5/tcp/123",
		"/ip4/8.6.3.2/udp/765",
		"/ip4/36.15.23.85/udp/8654/quic-v1",
		"/dns/test.com/udp/1543/quic-v1",
	}

	privateMaddrStrs := []string{
		"/ip4/192.168.0.1/tcp/123",
		"/ip4/127.0.0.1/udp/2345",
		"/ip4/172.18.0.2/udp/456/quic-v1",
		"/dns/localhost/tcp/123",
	}

	testPublicMaddrs := getValidMultiaddrs(publicMaddrStrs)
	testPrivateMaddrs := getValidMultiaddrs(privateMaddrStrs)

	testMaddrs := append(testPublicMaddrs, testPrivateMaddrs...)

	t.Run("Test categorization of multiaddrs into public and private", func(t *testing.T) {
		publicMaddrs, privateMaddrs := categorizePublicPrivateMultiaddrs(testMaddrs)
		assert.Equal(t, len(testPublicMaddrs), len(publicMaddrs))
		assert.Equal(t, len(testPrivateMaddrs), len(privateMaddrs))
		for _, maddr := range publicMaddrs {
			assert.Contains(t, publicMaddrStrs, maddr.String())
			assert.NotContains(t, privateMaddrStrs, maddr.String())
		}
		for _, maddr := range privateMaddrs {
			assert.Contains(t, privateMaddrStrs, maddr.String())
			assert.NotContains(t, publicMaddrStrs, maddr.String())
		}
	})
}

func Test_getValidMultiaddrs(t *testing.T) {
	validMaddrsStrs := []string{
		"/ip4/127.0.0.1/tcp/123",
		"/ip6/::1/udp/234",
		"/dns/localhost/udp/456/quic-v1",
		"/ip6/::ffff:15.32.65.95/tcp/123",
		"/ip6/2001:db8:85a3::8a2e:370:7334/tcp/123",
	}

	invalidMaddrStrs := []string{
		"/ip/127.0.0.1/tcp/123",
		"/ip4/127.0.0.1/123",
		"/ip4/127.0.0.1/tcp/",
		"/",
		"/ip4/127.0.0.1/tcp/123/quicv1",
		"/ip4/127.0.0.1/udp/123/qui",
		"/ip6/2001:db8:85a3:8a2e:370:7334/tcp/123",
	}

	testMaddrStrs := append(validMaddrsStrs, invalidMaddrStrs...)

	t.Run("Test valid multiaddr extraction from string array", func(t *testing.T) {
		maddrs := getValidMultiaddrs(testMaddrStrs)
		assert.Equal(t, len(validMaddrsStrs), len(maddrs))
		for _, maddr := range maddrs {
			assert.Contains(t, validMaddrsStrs, maddr.String())
			assert.NotContains(t, invalidMaddrStrs, maddr.String())
		}
	})
}

func Test_replaceMultiaddrIP(t *testing.T) {

	t.Run("IPv4-IPv4", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/ip4/192.168.0.3/tcp/123")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("15.32.65.95")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.NoError(t, err)
		assert.Equal(t, maddr.String(), "/ip4/15.32.65.95/tcp/123")
	})

	t.Run("IPv4-IPv6/4", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/ip4/192.168.0.3/tcp/123")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("::ffff:12.18.0.95")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.NoError(t, err)
		assert.Equal(t, maddr.String(), "/ip4/12.18.0.95/tcp/123")
	})

	t.Run("IPv4-IPv6", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/ip4/192.168.0.3/tcp/123")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("2001:db8:85a3::8a2e:370:7334")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.Error(t, err)
		assert.Nil(t, maddr)
	})

	t.Run("IPv6-IPv4", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/ip6/fd12:3456:789a:1:a:b:c:d/tcp/123")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("15.32.65.95")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.NoError(t, err)
		assert.Equal(t, maddr.String(), "/ip6/::ffff:15.32.65.95/tcp/123")
	})

	t.Run("IPv6/4-IPv4", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/ip6/::ffff:172.18.0.95/tcp/123")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("15.32.65.95")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.NoError(t, err)
		assert.Equal(t, maddr.String(), "/ip6/::ffff:15.32.65.95/tcp/123")
	})

	t.Run("IPv6/4-IPv6", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/ip6/::ffff:172.18.0.95/udp/123/quic-v1")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("2001:db8:85a3::8a2e:370:7334")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.NoError(t, err)
		assert.Equal(t, maddr.String(), "/ip6/2001:db8:85a3::8a2e:370:7334/udp/123/quic-v1")
	})

	t.Run("IPv6-IPv6", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/ip6/::ffff:172.18.0.95/tcp/123")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("2001:db8:85a3::8a2e:370:7334")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.NoError(t, err)
		assert.Equal(t, maddr.String(), "/ip6/2001:db8:85a3::8a2e:370:7334/tcp/123")
	})

	t.Run("DNS-IPv6", func(t *testing.T) {
		privateMaddr, err := ma.NewMultiaddr("/dns/test.com/tcp/123")
		assert.NoError(t, err)
		newIP, err := netip.ParseAddr("2001:db8:85a3::8a2e:370:7334")
		assert.NoError(t, err)
		maddr, err := replaceMultiaddrIP(privateMaddr, newIP)
		assert.Error(t, err)
		assert.Nil(t, maddr)
	})

}
