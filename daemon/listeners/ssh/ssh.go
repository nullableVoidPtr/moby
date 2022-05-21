package ssh // import "github.com/docker/docker/daemon/listeners/ssh"

import (
	"fmt"
	"io/ioutil"
	"net"

	"github.com/docker/go-connections/sockets"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

//TODO(nullableVoidPtr) move everything to go-connections
type Config struct {
	AuthorizedKeysFile    string
	TrustedUserCAKeysFile string
	HostCertificateFile   string
	HostKeyFile           string
}

type Listener struct {
	tl                   net.Listener
	config               *ssh.ServerConfig
	acceptedChannelConns chan ChannelConnection
}

func (sl Listener) demux(conn net.Conn) error {
	defer conn.Close()

	_, newChannelRequests, globalRequests, err := ssh.NewServerConn(conn, sl.config)
	if err != nil {
		return err
	}

	// Ignore global requests (usually port forwards)
	go ssh.DiscardRequests(globalRequests)

	go func(conn net.Conn, out chan<- ChannelConnection, in <-chan ssh.NewChannel) {
		for channel := range in {
			if channel.ChannelType() != "session" {
				channel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}

			channel, requests, err := channel.Accept()
			if err != nil {
				logrus.Fatalf("Could not accept channel: %v", err)
			}

			// Could look at using in-channel requests for
			// A better call and response protocol using
			// "subsystem" type requests, but using the duplex
			// channel as a transport for HTTP would suffice
			go ssh.DiscardRequests(requests)

			out <- ChannelConnection{
				c:    channel,
				conn: conn,
			}
		}
	}(conn, sl.acceptedChannelConns, newChannelRequests)

	return nil
}

func (sl Listener) Serve() error {
	var (
		tcpConn net.Conn
		err     error
	)
	for {
		tcpConn, err = sl.tl.Accept()
		if err != nil {
			return err
		}

		go sl.demux(tcpConn)
		return nil
	}
}

func (sl Listener) Accept() (net.Conn, error) {
	channel := <-sl.acceptedChannelConns
	return channel, nil
}

func (sl Listener) Close() error {
	return sl.tl.Close()
}

func (sl Listener) Addr() net.Addr {
	return sl.tl.Addr()
}

// listenSSH returns a listener which demultiplexes SSH connections and
// handles SSH channels as a net.Conn. This allows for multplexing over
// a single TCP connection; useful with docker-compose
func listenSSH(addr string, sshConfig *Config) (net.Listener, error) {
	// socket activation
	if sshConfig == nil {
		return nil, errors.New("Missing SSHConfig")
	}

	privateBytes, err := ioutil.ReadFile(sshConfig.HostKeyFile)
	if err != nil {
		logrus.Fatalf("Failed to load private key: %v", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logrus.Fatalf("Failed to parse private key: %v", err)
	}

	if sshConfig.AuthorizedKeysFile == "" && sshConfig.TrustedUserCAKeysFile == "" {
		logrus.Fatal("Neither AuthorizedKeys or TrustedUserCAKeys were specified")
	}

	authorizedKeysMap := map[string]bool{}
	if sshConfig.AuthorizedKeysFile != "" {
		authorizedKeysBytes, err := ioutil.ReadFile(sshConfig.AuthorizedKeysFile)
		if err != nil {
			logrus.Fatalf("Failed to load AuthorizedKeys: %v", err)
		}

		for len(authorizedKeysBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
			if err != nil {
				logrus.Fatal(err)
			}

			authorizedKeysMap[string(pubKey.Marshal())] = true
			authorizedKeysBytes = rest
		}
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("Unauthorized key %q", c.User())
		},
	}

	config.AddHostKey(private)

	if err != nil {
		return nil, err
	}

	tl, err := sockets.NewTCPSocket(addr, nil)
	if err != nil {
		return nil, err
	}

	var listener = Listener{
		tl:                   tl,
		config:               config,
		acceptedChannelConns: make(chan ChannelConnection),
	}

	go listener.Serve()

	return listener, nil
}

func Init(addr string, sshConfig *Config) ([]net.Listener, error) {
	sl, err := listenSSH(addr, sshConfig)
	if err != nil {
		return nil, err
	}

	return []net.Listener{sl}, nil
}
