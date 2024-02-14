//go:build !linux
// +build !linux

package ping

func listenPacket2(network, address, deviceToBind string) (*PacketConn, error) {
	return nil, errNotImplemented
}
