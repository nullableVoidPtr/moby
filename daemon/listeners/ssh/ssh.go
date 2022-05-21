package ssh // import "github.com/docker/docker/daemon/listeners/ssh"

import (
	"encoding/binary"
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
	logrus.Infof("Accept SSH connection from: %v", conn)
	_, newChannelRequests, globalRequests, err := ssh.NewServerConn(conn, sl.config)
	if err != nil {
		return err
	}

	// Ignore global requests (usually port forwards)
	go ssh.DiscardRequests(globalRequests)

	go func() {
		defer conn.Close()
		for chanReq := range newChannelRequests {
			if chanReq.ChannelType() != "session" {
				chanReq.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}

			channel, requests, err := chanReq.Accept()
			if err != nil {
				logrus.Fatalf("Could not accept channel: %v", err)
			}

			// Could look at using in-channel requests for
			// A better call and response protocol using
			// "subsystem" type requests, but using the duplex
			// channel as a transport for HTTP would suffice
			go func() {
				for req := range requests {
					// Compatibility with legacy Docker CLI ConnHelper
					if req.Type == "exec" {
						cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
						if uint32(binary.Size(req.Payload[4:])) != cmdLen || string(req.Payload[4:]) != "docker system dial-stdio" {
							req.Reply(false, nil)
						}

						req.Reply(true, nil)
					}
					req.Reply(false, nil)
				}
			}()

			sl.acceptedChannelConns <- ChannelConnection{
				c:    channel,
				conn: conn,
			}
		}
	}()

	return nil
}

func (sl Listener) Serve() error {
	for {
		tcpConn, err := sl.tl.Accept()
		if err != nil {
			return err
		}

		go sl.demux(tcpConn)
	}

	return nil
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

	hostKeyBytes, err := ioutil.ReadFile(sshConfig.HostKeyFile)
	if err != nil {
		logrus.Fatalf("Failed to load private key: %v", err)
	}

	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		logrus.Fatalf("Failed to parse private key: %v", err)
	}

	if sshConfig.AuthorizedKeysFile == "" && sshConfig.TrustedUserCAKeysFile == "" {
		logrus.Fatal("Neither AuthorizedKeys or TrustedUserCAKeys were specified")
	}

	authenticator := func(conn ssh.ConnMetadata, userKey ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, fmt.Errorf("Unauthorized key %q", conn.User())
	}

	if sshConfig.AuthorizedKeysFile != "" {
		authorizedKeys := map[string]bool{}
		authorizedKeysBytes, err := ioutil.ReadFile(sshConfig.AuthorizedKeysFile)
		if err != nil {
			logrus.Fatalf("Failed to load AuthorizedKeys: %v", err)
		}

		for len(authorizedKeysBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
			if err != nil {
				logrus.Fatal(err)
			}

			authorizedKeys[string(pubKey.Marshal())] = true
			authorizedKeysBytes = rest
		}
		authenticator = func(conn ssh.ConnMetadata, userKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeys[string(userKey.Marshal())] {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("Unauthorized key %q", conn.User())
		}
	}

	if sshConfig.TrustedUserCAKeysFile != "" {
		userCAKeys := map[string]bool{}
		trustedUserCAKeysBytes, err := ioutil.ReadFile(sshConfig.TrustedUserCAKeysFile)
		if err != nil {
			logrus.Fatalf("Failed to load AuthorizedKeys: %v", err)
		}

		for len(trustedUserCAKeysBytes) > 0 {
			userCAKey, _, _, rest, err := ssh.ParseAuthorizedKey(trustedUserCAKeysBytes)
			if err != nil {
				logrus.Fatal(err)
			}

			userCAKeys[string(userCAKey.Marshal())] = true
			trustedUserCAKeysBytes = rest
		}

		certChecker := ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return userCAKeys[string(auth.Marshal())]
			},
			UserKeyFallback: authenticator,
		}
		authenticator = certChecker.Authenticate
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: authenticator,
	}

	if sshConfig.HostCertificateFile != "" {
		hostCertificateBytes, err := ioutil.ReadFile(sshConfig.HostCertificateFile)
		if err != nil {
			logrus.Fatalf("Failed to load host key certificate: %v", err)
		}

		for len(hostCertificateBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(hostCertificateBytes)
			if err != nil {
				logrus.Fatal(err)
			}

			certificate := pubKey.(*ssh.Certificate)

			signedHostKey, err := ssh.NewCertSigner(certificate, hostKey)
			if err != nil {
				logrus.Warn(err)
				hostCertificateBytes = rest
				continue
			}

			config.AddHostKey(signedHostKey)
			hostCertificateBytes = rest
		}
	} else {
		config.AddHostKey(hostKey)
	}

	if err != nil {
		return nil, err
	}

	tl, err := sockets.NewTCPSocket(addr, nil)
	if err != nil {
		return nil, err
	}

	listener := Listener{
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
