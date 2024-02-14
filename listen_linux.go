//go:build linux
// +build linux

package ping

import (
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

//
// code from: golang.org/x.net/icmp/listen_posix.go
// see origin file copyright
// add bind device support

const (
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
	ProtocolIP       = 0
	sysIP_STRIPHDR   = 0x17
)

var (
	errInvalidConn      = errors.New("invalid connection")
	errInvalidProtocol  = errors.New("invalid protocol")
	errMessageTooShort  = errors.New("message too short")
	errHeaderTooShort   = errors.New("header too short")
	errBufferTooShort   = errors.New("buffer too short")
	errInvalidBody      = errors.New("invalid body")
	errNoExtension      = errors.New("no extension")
	errInvalidExtension = errors.New("invalid extension")
	errNotImplemented   = errors.New("not implemented on " + runtime.GOOS + "/" + runtime.GOARCH)
)

func sockaddr(family int, address string) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		a, err := net.ResolveIPAddr("ip4", address)
		if err != nil {
			return nil, err
		}
		if len(a.IP) == 0 {
			a.IP = net.IPv4zero
		}
		if a.IP = a.IP.To4(); a.IP == nil {
			return nil, net.InvalidAddrError("non-ipv4 address")
		}
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], a.IP)
		return sa, nil
	case syscall.AF_INET6:
		a, err := net.ResolveIPAddr("ip6", address)
		if err != nil {
			return nil, err
		}
		if len(a.IP) == 0 {
			a.IP = net.IPv6unspecified
		}
		if a.IP.Equal(net.IPv4zero) {
			a.IP = net.IPv6unspecified
		}
		if a.IP = a.IP.To16(); a.IP == nil || a.IP.To4() != nil {
			return nil, net.InvalidAddrError("non-ipv6 address")
		}
		sa := &syscall.SockaddrInet6{ZoneId: zoneToUint32(a.Zone)}
		copy(sa.Addr[:], a.IP)
		return sa, nil
	default:
		return nil, net.InvalidAddrError("unexpected family")
	}
}

func zoneToUint32(zone string) uint32 {
	if zone == "" {
		return 0
	}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return uint32(ifi.Index)
	}
	n, err := strconv.Atoi(zone)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func last(s string, b byte) int {
	i := len(s)
	for i--; i >= 0; i-- {
		if s[i] == b {
			break
		}
	}
	return i
}

// A PacketConn represents a packet network endpoint that uses either
// ICMPv4 or ICMPv6.
type PacketConn struct {
	c  net.PacketConn
	p4 *ipv4.PacketConn
	p6 *ipv6.PacketConn
}

func (c *PacketConn) ok() bool { return c != nil && c.c != nil }

// IPv4PacketConn returns the ipv4.PacketConn of c.
// It returns nil when c is not created as the endpoint for ICMPv4.
func (c *PacketConn) IPv4PacketConn() *ipv4.PacketConn {
	if !c.ok() {
		return nil
	}
	return c.p4
}

// IPv6PacketConn returns the ipv6.PacketConn of c.
// It returns nil when c is not created as the endpoint for ICMPv6.
func (c *PacketConn) IPv6PacketConn() *ipv6.PacketConn {
	if !c.ok() {
		return nil
	}
	return c.p6
}

// ReadFrom reads an ICMP message from the connection.
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !c.ok() {
		return 0, nil, errInvalidConn
	}
	// Please be informed that ipv4.NewPacketConn enables
	// IP_STRIPHDR option by default on Darwin.
	// See golang.org/issue/9395 for further information.
	if (runtime.GOOS == "darwin" || runtime.GOOS == "ios") && c.p4 != nil {
		n, _, peer, err := c.p4.ReadFrom(b)
		return n, peer, err
	}
	return c.c.ReadFrom(b)
}

// WriteTo writes the ICMP message b to dst.
// The provided dst must be net.UDPAddr when c is a non-privileged
// datagram-oriented ICMP endpoint.
// Otherwise it must be net.IPAddr.
func (c *PacketConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if !c.ok() {
		return 0, errInvalidConn
	}
	return c.c.WriteTo(b, dst)
}

// Close closes the endpoint.
func (c *PacketConn) Close() error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.Close()
}

// LocalAddr returns the local network address.
func (c *PacketConn) LocalAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.c.LocalAddr()
}

// SetDeadline sets the read and write deadlines associated with the
// endpoint.
func (c *PacketConn) SetDeadline(t time.Time) error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the
// endpoint.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the
// endpoint.
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.SetWriteDeadline(t)
}

func listenPacket2(network, address, deviceToBind string) (*PacketConn, error) {
	var family, proto int
	switch network {
	case "udp4":
		family, proto = syscall.AF_INET, ProtocolICMP
	case "udp6":
		family, proto = syscall.AF_INET6, ProtocolIPv6ICMP
	default:
		i := last(network, ':')
		if i < 0 {
			i = len(network)
		}
		switch network[:i] {
		case "ip4":
			proto = ProtocolICMP
		case "ip6":
			proto = ProtocolIPv6ICMP
		}
	}
	var cerr error
	var c net.PacketConn
	switch family {
	case syscall.AF_INET, syscall.AF_INET6:
		s, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}
		if (runtime.GOOS == "darwin" || runtime.GOOS == "ios") && family == syscall.AF_INET {
			if err := syscall.SetsockoptInt(s, ProtocolIP, sysIP_STRIPHDR, 1); err != nil {
				_ = syscall.Close(s)
				return nil, os.NewSyscallError("setsockopt", err)
			}
		}
		sa, err := sockaddr(family, address)
		if err != nil {
			_ = syscall.Close(s)
			return nil, err
		}

		if err := syscall.Bind(s, sa); err != nil {
			_ = syscall.Close(s)
			return nil, os.NewSyscallError("bind", err)
		}

		if err := syscall.BindToDevice(s, deviceToBind); err != nil {
			_ = syscall.Close(s)
			return nil, os.NewSyscallError("BindToDevice", err)
		}

		f := os.NewFile(uintptr(s), "datagram-oriented icmp")
		c, cerr = net.FilePacketConn(f)
		_ = f.Close()
	default:
		c, cerr = net.ListenPacket(network, address)
	}
	if cerr != nil {
		return nil, cerr
	}

	switch proto {
	case ProtocolICMP:
		return &PacketConn{c: c, p4: ipv4.NewPacketConn(c)}, nil
	case ProtocolIPv6ICMP:
		return &PacketConn{c: c, p6: ipv6.NewPacketConn(c)}, nil
	default:
		return &PacketConn{c: c}, nil
	}
}

type icmpConn2 struct {
	c   *PacketConn
	ttl int
}

func (c *icmpConn2) Close() error {
	return c.c.Close()
}

func (c *icmpConn2) SetTTL(ttl int) {
	c.ttl = ttl
}

func (c *icmpConn2) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *icmpConn2) WriteTo(b []byte, dst net.Addr) (int, error) {
	if c.c.IPv6PacketConn() != nil {
		if err := c.c.IPv6PacketConn().SetHopLimit(c.ttl); err != nil {
			return 0, err
		}
	}
	if c.c.IPv4PacketConn() != nil {
		if err := c.c.IPv4PacketConn().SetTTL(c.ttl); err != nil {
			return 0, err
		}
	}

	return c.c.WriteTo(b, dst)
}

type icmpv4Conn2 struct {
	icmpConn2
}

func (c *icmpv4Conn2) SetFlagTTL() error {
	err := c.c.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpv4Conn2) ReadFrom(b []byte) (int, int, net.Addr, error) {
	ttl := -1
	n, cm, src, err := c.c.IPv4PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.TTL
	}
	return n, ttl, src, err
}

func (c icmpv4Conn2) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

type icmpV6Conn2 struct {
	icmpConn2
}

func (c *icmpV6Conn2) SetFlagTTL() error {
	err := c.c.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpV6Conn2) ReadFrom(b []byte) (int, int, net.Addr, error) {
	ttl := -1
	n, cm, src, err := c.c.IPv6PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.HopLimit
	}
	return n, ttl, src, err
}

func (c icmpV6Conn2) ICMPRequestType() icmp.Type {
	return ipv6.ICMPTypeEchoRequest
}
