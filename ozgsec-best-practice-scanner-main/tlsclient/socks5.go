package tlsclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"errors"

	"golang.org/x/net/proxy"
)

var ErrProxyConnectionFailed = errors.New("proxy connection failed")

type socks5 struct {
	serverURL string
	auth      *proxy.Auth
}

// use a string to specify the server and port
// e.g. "98.185.94.94:4145"
func NewSOCKS5(serverURL *url.URL) socks5 {
	username := serverURL.User.Username()
	password, isSet := serverURL.User.Password()

	var auth *proxy.Auth = nil
	if isSet {
		auth = &proxy.Auth{
			User:     username,
			Password: password,
		}
	}

	return socks5{
		serverURL: serverURL.Hostname() + ":" + serverURL.Port(),
		auth:      auth,
	}
}

type dialResponse struct {
	conn net.Conn
	err  error
}

func (p socks5) Get(ctx context.Context, target *url.URL, tlsConfig *tls.Config) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", p.serverURL, p.auth, &net.Dialer{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, errors.Join(err, ErrProxyConnectionFailed)
	}

	// WARNING: proxy does not support to use a context for dialing
	// therefore we spawn a goroutine - which MIGHT LEAK
	resChan := make(chan dialResponse)

	go func() {
		conn, err := dialer.Dial("tcp", target.Hostname()+":"+target.Port()) // might block forever
		if err != nil {
			return
		}
		// upgrade the proxy connection to tls
		tlsConn := tls.Client(conn, tlsConfig)
		resChan <- dialResponse{
			conn: tlsConn,
			err:  tlsConn.Handshake(),
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resChan:
		return res.conn, res.err
	}
}
