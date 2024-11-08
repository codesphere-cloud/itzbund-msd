package tlsclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
)

type defaultClient struct {
}

func NewDefaultClient() defaultClient {
	return defaultClient{}
}

func (p defaultClient) Get(ctx context.Context, target *url.URL, tlsConfig *tls.Config) (net.Conn, error) {
	dialer := &tls.Dialer{
		Config: tlsConfig,
	}
	conn, err := dialer.DialContext(ctx, "tcp", target.Hostname()+":"+target.Port())
	if err != nil {
		return nil, err
	}
	return conn, nil
}
