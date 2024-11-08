package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/tlsclient"
)

func TestTLS(t *testing.T) {
	insecureSkipVerify = true
	table := []struct {
		expectSuccess []AnalysisRuleId
		expectFailed  []AnalysisRuleId
		tlsVersion    uint16
	}{
		{
			expectSuccess: []AnalysisRuleId{TLS12, DeprecatedTLSDeactivated},
			expectFailed:  []AnalysisRuleId{TLS13},
			tlsVersion:    tls.VersionTLS12,
		},
		{
			expectSuccess: []AnalysisRuleId{(TLS13), DeprecatedTLSDeactivated},
			expectFailed:  []AnalysisRuleId{TLS12},
			tlsVersion:    tls.VersionTLS13,
		},
		{
			expectSuccess: []AnalysisRuleId{},
			expectFailed:  []AnalysisRuleId{TLS12, TLS13, DeprecatedTLSDeactivated},
			tlsVersion:    tls.VersionTLS10,
		},
	}

	for _, test := range table {
		t.Run(fmt.Sprint(test.tlsVersion), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			server.TLS = &tls.Config{ // nolint // we are using the min tls version on purpose
				MinVersion: test.tlsVersion,
				MaxVersion: test.tlsVersion,
			}
			server.StartTLS()
			defer server.Close()

			target, _ := url.Parse(server.URL)

			inspector := NewTLSAnalyzer()
			res, _ := inspector.Analyze(context.Background(), Target{URL: target, IPV4Address: net.ParseIP(target.Hostname()), Options: TargetScanOptions{
				TlsClient: tlsclient.NewDefaultClient(),
				EnabledChecks: map[AnalysisRuleId]bool{
					TLS12:                    true,
					TLS13:                    true,
					DeprecatedTLSDeactivated: true,
				},
			}}, nil)

			for _, expect := range test.expectSuccess {
				actual := res[expect]
				if *actual.DidPass != true {
					t.Error("Expected to pass", expect, *actual.DidPass)
				}
			}

			for _, expect := range test.expectFailed {
				actual := res[expect]
				if *actual.DidPass != false {
					t.Error("Expected to fail", expect)
				}
			}
		})
	}
}

func TestStrongCipherSuites(t *testing.T) {
	insecureSkipVerify = true
	table := []struct {
		cipherSuite uint16
		expected    bool
		tlsVersion  uint16
	}{
		{
			cipherSuite: tls.TLS_AES_128_GCM_SHA256,
			expected:    true,
			tlsVersion:  tls.VersionTLS13,
		},
		{
			cipherSuite: tls.TLS_AES_256_GCM_SHA384,
			expected:    true,
			tlsVersion:  tls.VersionTLS13,
		},

		{
			cipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			expected:    true,
			tlsVersion:  tls.VersionTLS12,
		},
		{
			cipherSuite: tls.TLS_CHACHA20_POLY1305_SHA256,
			expected:    false,
			tlsVersion:  tls.VersionTLS12,
		},
	}

	for i, test := range table {
		t.Run(fmt.Sprint(test.cipherSuite), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			server.TLS = &tls.Config{
				MinVersion: test.tlsVersion,
				MaxVersion: test.tlsVersion,
				CipherSuites: []uint16{
					test.cipherSuite, // nolint
				},
			}
			server.StartTLS()
			defer server.Close()

			target, _ := url.Parse(server.URL)

			inspector := NewTLSAnalyzer()
			res, _ := inspector.Analyze(context.Background(), Target{URL: target, IPV4Address: net.ParseIP(target.Hostname()), Options: TargetScanOptions{
				TlsClient: tlsclient.NewDefaultClient(),
				EnabledChecks: map[AnalysisRuleId]bool{
					TLS12:                    true,
					TLS13:                    true,
					DeprecatedTLSDeactivated: true,
				},
			}}, nil)

			actual := res[StrongCipherSuites]
			if *actual.DidPass != test.expected {
				t.Error(i, "Expected to be ", test.expected, " but was", *actual.DidPass)
			}
		})

	}
}
