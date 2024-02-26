//go:build linux
// +build linux

package ping

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
)

func (p *Pinger) resolve1() error {
	p.logger.Debugf("resolve1")
	// check is ip address
	if ip, err := netip.ParseAddr(p.addr); err == nil {
		addr := &net.IPAddr{
			IP:   net.IP(ip.AsSlice()).To16(),
			Zone: ip.Zone(),
		}
		p.ipv4 = isIPv4(addr.IP)
		p.ipaddr = addr

		p.logger.Debugf("addr is ip, skip dns resolve")
		return nil
	}

	lookupIp := func(dns, network, addr string) (net.IP, error) {
		r := net.Resolver{
			PreferGo:     true,
			StrictErrors: false,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					ControlContext: func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
						if p.BindInterface != "" {
							p.logger.Debugf("bind to interface: %s, resolve dns", p.BindInterface)
							_ = c.Control(func(fd uintptr) {
								err = syscall.BindToDevice(int(fd), p.BindInterface)
								if err != nil {
									err = os.NewSyscallError("BindToDevice", err)
								}
							})
						}

						return
					},
				}

				if p.Source != "" {
					p.logger.Debugf("bind dns dialer to source: %s", p.Source)
					ip, err := net.ResolveIPAddr("", p.Source)
					if err != nil {
						return nil, err
					}

					d.LocalAddr = ip
				}

				if dns != "" {
					address := net.JoinHostPort(dns, "53")
					p.logger.Debugf("dial dns: %s", address)
					return d.DialContext(ctx, network, address)
				} else {
					p.logger.Debugf("dial dns: %s", address)
					return d.DialContext(ctx, network, address)
				}
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p.logger.Debugf("lookup ip: %s, network: %s", addr, network)
		ipList, err := r.LookupIP(ctx, network, addr)
		cancel()

		if err != nil {
			return nil, err
		}

		for _, ip := range ipList {
			p.logger.Debugf("lookup ip return: %s", ip.String())
		}

		if len(ipList) == 1 { // only one ip
			return ipList[0], nil
			/*p.ipv4 = isIPv4(ipList[0])
			p.ipaddr = &net.IPAddr{
				IP:   ipList[0],
				Zone: "",
			}*/
		}

		switch network {
		case "ip": // return first
			return ipList[0], nil
		case "ip4":
			for _, ip := range ipList {
				if isIPv4(ip) {
					return ip, nil
				}
			}

			return nil, &net.DNSError{
				Err:         "no ipv4 addr",
				Name:        addr,
				Server:      dns,
				IsTimeout:   false,
				IsTemporary: false,
				IsNotFound:  true,
			}
		case "ip6":
			for _, ip := range ipList {
				if !isIPv4(ip) {
					return ip, nil
				}
			}

			return nil, &net.DNSError{
				Err:         "no ipv6 addr",
				Name:        addr,
				Server:      dns,
				IsTimeout:   false,
				IsTemporary: false,
				IsNotFound:  true,
			}
		default:
			return nil, &net.DNSError{
				Err:         "unknown network",
				Name:        addr,
				Server:      dns,
				IsTimeout:   false,
				IsTemporary: false,
				IsNotFound:  false,
			}
		}
	}

	dnsList := strings.Split(p.DNS, ";")
	p.logger.Debugf("resolve by dns list: %#v", dnsList)
	for index, dns := range dnsList {
		ip, err := lookupIp(dns, p.network, p.addr)
		if err == nil {
			p.ipv4 = isIPv4(ip)
			p.ipaddr = &net.IPAddr{
				IP:   ip,
				Zone: "",
			}

			return nil
		}

		if err != nil {
			p.logger.Warnf("lookup dns: %s, error: %s", dns, err.Error())
		}

		if err != nil && index == len(dns)-1 { // last dns
			return err
		}
	}

	return &net.DNSError{
		Err:         "no such host",
		Name:        p.addr,
		Server:      "",
		IsTimeout:   false,
		IsTemporary: false,
		IsNotFound:  true,
	}
}

func (p *Pinger) listen() (packetConn, error) {
	var (
		conn packetConn
		err  error
	)

	if p.BindInterface != "" {
		if p.ipv4 {
			p.logger.Debugf("listenPacket2, network: %s, address: %s, interface: %s", ipv4Proto[p.protocol], p.Source, p.BindInterface)
			var c icmpv4Conn2
			c.c, err = listenPacket2(ipv4Proto[p.protocol], p.Source, p.BindInterface)
			conn = &c
		} else {
			p.logger.Debugf("listenPacket2, network: %s, address: %s, interface: %s", ipv6Proto[p.protocol], p.Source, p.BindInterface)
			var c icmpV6Conn2
			c.c, err = listenPacket2(ipv6Proto[p.protocol], p.Source, p.BindInterface)
			conn = &c
		}
	} else {
		if p.ipv4 {
			var c icmpv4Conn
			c.c, err = icmp.ListenPacket(ipv4Proto[p.protocol], p.Source)
			conn = &c
		} else {
			var c icmpV6Conn
			c.c, err = icmp.ListenPacket(ipv6Proto[p.protocol], p.Source)
			conn = &c
		}
	}

	if err != nil {
		p.Stop()
		return nil, err
	}
	return conn, nil
}
