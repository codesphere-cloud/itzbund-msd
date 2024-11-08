package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
)

func TestHttp(t *testing.T) {
	table := []struct {
		statusCode int
		expected   bool
	}{
		{200, true},
		{201, true},
		{404, true}, // at least it does offer http
		{500, false},
	}

	for _, test := range table {

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.statusCode)
		}))

		defer server.Close()

		client := httpclient.NewRedirectAwareHttpClient(nil)

		target, _ := url.Parse(server.URL)
		resp, _ := client.Get(context.Background(), target)

		inspector := NewHttpAnalyzer()

		res, _ := inspector.Analyze(context.Background(), Target{
			Options: TargetScanOptions{
				EnabledChecks: map[AnalysisRuleId]bool{
					HTTP: true,
				},
			},
		}, resp)

		if *res[HTTP].DidPass != test.expected {
			t.Error("Expected to fail")
		}
	}
}

func TestFailHttpRedirectsToHttps(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			r.URL.Path = "/"
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := httpclient.NewRedirectAwareHttpClient(nil)

	target, _ := url.Parse(server.URL)
	target.Path = "/redirect"
	resp, _ := client.Get(context.Background(), target)

	inspector := NewHttpAnalyzer()

	res, _ := inspector.Analyze(context.Background(), Target{
		Options: TargetScanOptions{
			EnabledChecks: map[AnalysisRuleId]bool{
				HTTPRedirectsToHttps: true,
			},
		},
	}, resp)

	if *res[HTTPRedirectsToHttps].DidPass != false {
		t.Error("Expected to fail")
	}

}

func TestHttp308(t *testing.T) {
	table := []struct {
		statusCode int
		expected   bool
	}{
		{308, true},
		{307, false},
		{301, false},
		{302, false},
		{303, false},
	}

	for _, test := range table {
		t.Run(fmt.Sprintf("StatusCode: %d, expected: %v", test.statusCode, test.expected), func(t *testing.T) {

			tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer tlsServer.Close()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tlsServer.URL, test.statusCode)
			}))
			defer server.Close()

			client := httpclient.NewRedirectAwareHttpClient(&http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // nolint
				},
			})

			target, _ := url.Parse(server.URL)
			resp, _ := client.Get(context.Background(), target)

			inspector := NewHttpAnalyzer()

			res, _ := inspector.Analyze(context.Background(), Target{
				Options: TargetScanOptions{
					EnabledChecks: map[AnalysisRuleId]bool{
						HTTP308: true,
					},
				},
			}, resp)

			if *res[HTTP308].DidPass != test.expected {
				t.Error("Expected to", test.expected, "but got", *res[HTTP308].DidPass)
			}
		})
	}
}
