package ssh // import "github.com/docker/docker/daemon/listeners/ssh"

import (
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type ChannelConnection struct {
	c    ssh.Channel
	conn net.Conn
	// read_deadline time.Time
	// write_deadline time.Time
}

func (cc ChannelConnection) Read(b []byte) (int, error) {
	return cc.c.Read(b)
}

func (cc ChannelConnection) Write(b []byte) (int, error) {
	return cc.c.Write(b)
}

func (cc ChannelConnection) Close() error {
	return cc.c.Close()
}

func (cc ChannelConnection) LocalAddr() net.Addr {
	return cc.conn.LocalAddr()
}

func (cc ChannelConnection) RemoteAddr() net.Addr {
	return cc.conn.RemoteAddr()
}

//TODO unsupported timeouts
func (cc ChannelConnection) SetDeadline(t time.Time) error {
	return nil
}

func (cc ChannelConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (cc ChannelConnection) SetWriteDeadline(t time.Time) error {
	return nil
}
