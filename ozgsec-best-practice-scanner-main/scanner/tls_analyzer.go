package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"net"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/concurrency"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/tlsclient"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

// this is the network controlled by the bsi.
var _, bsiNet, _ = net.ParseCIDR("77.87.228.0/22")

// REF: https://wiki.mozilla.org/Security/Server_Side_TLS
var tls13StrongCipherSuites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

// REF: https://wiki.mozilla.org/Security/Server_Side_TLS
var tls12StrongCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	// tls.TLS_DHE_RSA_AES128_GCM_SHA256, - not supported by golang
	// tls.TLS_DHE_RSA_AES256_GCM_SHA384, - not supported by golang
}

// just used for testing purposes. The value should be FALSE when running in production
var insecureSkipVerify = false

func tlsConnect(ctx context.Context, target Target, tlsConfig *tls.Config) (net.Conn, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:         target.URL.Hostname(),
			InsecureSkipVerify: insecureSkipVerify, // nolint // we are just interested in the tls stack - not if the certificate is valid
		}
	}

	port := target.URL.Port()
	if port == "" {
		port = "443"
	}

	rawUrl := target.IPV4Address.String() + ":" + port
	u, err := url.Parse("http://" + rawUrl)

	if err != nil {
		return nil, err
	}
	return target.Options.TlsClient.Get(ctx, u, tlsConfig)
}

func tlsVersionSupported(ctx context.Context, target Target, tlsVersion uint16) DidPass {
	config := tls.Config{
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
		ServerName:         target.URL.Hostname(),
		InsecureSkipVerify: insecureSkipVerify, // nolint // we are just interested in the tls stack - not if the certificate is valid
	}

	// check if the url does already specify a port _ than we can use it
	port := target.URL.Port()
	if port == "" {
		port = "443"
	}
	rawUrl := target.IPV4Address.String() + ":" + port
	u, err := url.Parse("http://" + rawUrl)
	if err != nil {
		return Unknown
	}

	conn, err := target.Options.TlsClient.Get(ctx, u, &config)

	if errors.Is(err, tlsclient.ErrProxyConnectionFailed) {
		slog.Info("proxy connection failed")
		return Unknown
	}
	if err != nil {
		// check if timeout
		if ctx.Err() != nil {
			return Unknown
		}
		return Failure
	}
	defer conn.Close()
	return Success
}

func tls12Supported(ctx context.Context, target Target) AnalysisResult {
	start := time.Now()
	didPass := tlsVersionSupported(ctx, target, tls.VersionTLS12)
	return NewAnalysisResult(didPass, nil, nil, nil, time.Since(start))
}

func tls13Supported(ctx context.Context, target Target) AnalysisResult {
	start := time.Now()
	didPass := tlsVersionSupported(ctx, target, tls.VersionTLS13)
	return NewAnalysisResult(didPass, nil, nil, nil, time.Since(start))
}

func deprecatedTLSDeactivated(ctx context.Context, target Target) AnalysisResult {
	start := time.Now()
	// do not try to connect to the bsi using deprecated tls protocols.
	// This will fail - and our ip will be blocked
	if bsiNet.Contains(target.IPV4Address) {
		return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
	}
	tls1 := tlsVersionSupported(ctx, target, tls.VersionTLS10)
	tls11 := tlsVersionSupported(ctx, target, tls.VersionTLS11)
	// check if both are null
	if tls1 == Unknown && tls11 == Unknown {
		return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
	}

	return NewAnalysisResult(ptr(tls1 == Failure && tls11 == Failure), map[string]any{
		"tlsv1_0Supported": tls1,
		"tlsv1_1Supported": tls11,
	}, nil, nil, time.Since(start))
}

func strongKeyExchange(_ context.Context, _ Target) AnalysisResult {
	return NewAnalysisResult(Unknown, nil, nil, nil, time.Duration(0))
}

func strongCipherSuitesSupported(ctx context.Context, target Target, state *tls.ConnectionState) AnalysisResult {
	start := time.Now()
	// try to reuse the connection
	if state != nil && state.Version == tls.VersionTLS13 && utils.Includes(tls13StrongCipherSuites, state.CipherSuite) {
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	} else if state != nil && state.Version == tls.VersionTLS12 && utils.Includes(tls12StrongCipherSuites, state.CipherSuite) {
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	}

	conn, err := tlsConnect(ctx, target, &tls.Config{
		ServerName:         target.URL.Hostname(),
		InsecureSkipVerify: insecureSkipVerify, // nolint // we are just interested in the tls stack - not if the certificate is valid
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       tls13StrongCipherSuites,
	})

	if err == nil {
		conn.Close()
		// it does not support strong ciphers for tls13
		return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
	}
	// lets check tls12
	conn, err = tlsConnect(ctx, target, &tls.Config{
		ServerName:         target.URL.Hostname(),
		InsecureSkipVerify: insecureSkipVerify, // nolint // we are just interested in the tls stack - not if the certificate is valid
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       tls12StrongCipherSuites,
	})
	if err != nil {
		if ctx.Err() != nil {
			return NewAnalysisResult(Unknown, nil, nil, nil, time.Since(start))
		}
		// it does not support strong ciphers for tls12
		return NewAnalysisResult(Failure, nil, nil, nil, time.Since(start))

	}
	conn.Close()
	return NewAnalysisResult(Success, nil, nil, nil, time.Since(start))
}

type tlsAnalyzer struct {
}

func NewTLSAnalyzer() analyzer[*tls.ConnectionState] {
	return tlsAnalyzer{}
}

func (t tlsAnalyzer) GetAnalysisRuleIds() []AnalysisRuleId {
	return []AnalysisRuleId{
		TLS12,
		TLS13,
		DeprecatedTLSDeactivated,
		HTTPS,
		StrongKeyExchange,
		StrongCipherSuites,
	}
}

// accepts an existing tls connection state to reuse it
// this does reduce the necessary tls connections to the target
func (t tlsAnalyzer) Analyze(ctx context.Context, target Target, state *tls.ConnectionState) (map[AnalysisRuleId]AnalysisResult, error) {
	res := concurrency.All(
		maybeDoCheckFactory(TLS12, target.Options, func() AnalysisResult {
			if state != nil && state.Version == tls.VersionTLS12 {
				return NewAnalysisResult(Success, nil, nil, nil, time.Duration(0))
			}
			return tls12Supported(ctx, target)
		}),
		maybeDoCheckFactory(TLS13, target.Options, func() AnalysisResult {
			if state != nil && state.Version == tls.VersionTLS13 {
				return NewAnalysisResult(Success, nil, nil, nil, time.Duration(0))
			}
			return tls13Supported(ctx, target)
		}),
		maybeDoCheckFactory(DeprecatedTLSDeactivated, target.Options, func() AnalysisResult {
			if state != nil && (state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11) {
				return NewAnalysisResult(Failure, nil, nil, nil, time.Duration(0))
			}
			return deprecatedTLSDeactivated(ctx, target)
		}))

	tls12 := res[0]
	tls13 := res[1]
	deprecatedTLSDeactivated := res[2]
	return map[AnalysisRuleId]AnalysisResult{
		TLS12:                    tls12,
		TLS13:                    tls13,
		DeprecatedTLSDeactivated: deprecatedTLSDeactivated,
		HTTPS:                    NewAnalysisResult(ptr(tls12.IsSuccess() || tls13.IsSuccess() || deprecatedTLSDeactivated.IsError()), nil, nil, nil, time.Duration(0)),
		StrongKeyExchange:        strongKeyExchange(ctx, target),
		StrongCipherSuites:       strongCipherSuitesSupported(ctx, target, state),
	}, nil
}
