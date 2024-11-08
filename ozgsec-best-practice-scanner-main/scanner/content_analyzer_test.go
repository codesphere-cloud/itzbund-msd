package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
)

func TestNoMixedContentFail(t *testing.T) {
	// start a test server, which provides an image with a http and an image with an https source
	// check if the result is false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// nolint
		w.Write([]byte(`<!DOCTYPE html> 
  <html>
  <body>
  <img src="http://example.com/image.png">
  <img src="https://example.com/image.png">
  </body>
  </html>`))
	}))
	defer server.Close()

	content := NewContentAnalyzer()
	client := httpclient.NewDefaultClient()

	uri, _ := url.Parse(server.URL)

	resp, _ := client.Get(context.Background(), uri)

	res, _ := content.Analyze(context.Background(), Target{
		Options: TargetScanOptions{
			EnabledChecks: map[AnalysisRuleId]bool{
				NoMixedContent: true,
			},
		},
	}, resp)

	noMixedContent := *res[NoMixedContent].DidPass

	if noMixedContent {
		t.Errorf("Expected %s to fail, but it passed", NoMixedContent)
	}
}

func TestPassIfBothHttpSources(t *testing.T) {
	// start a test server, which provides an image with a http and an image with an http source
	// check if the result is true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// nolint
		w.Write([]byte(`<!DOCTYPE html>
  <html>
  <body>
  <img src="http://example.com/image.png">
  <img src="http://example.com/image.png">
  </body>
  </html>`))
	}))
	defer server.Close()

	content := NewContentAnalyzer()
	client := httpclient.NewDefaultClient()

	uri, _ := url.Parse(server.URL)

	resp, _ := client.Get(context.Background(), uri)

	res, _ := content.Analyze(context.Background(), Target{
		Options: TargetScanOptions{
			EnabledChecks: map[AnalysisRuleId]bool{
				NoMixedContent: true,
			},
		},
	}, resp)
	noMixedContent := *res[NoMixedContent].DidPass

	if !noMixedContent {
		t.Errorf("Expected %s to pass, but it failed", NoMixedContent)
	}
}

func TestPassIfAllHttpsSources(t *testing.T) {
	// start a test server, which provides an image with a https and an image with an https source
	// check if the result is true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// nolint
		w.Write([]byte(`<!DOCTYPE html> 
  <html>
  <body>
  <img src="https://example.com/image.png">
  <img src="https://example.com/image.png">
  </body>
  </html>`))
	}))
	defer server.Close()

	content := NewContentAnalyzer()
	client := httpclient.NewDefaultClient()

	uri, _ := url.Parse(server.URL)

	resp, _ := client.Get(context.Background(), uri)

	res, _ := content.Analyze(context.Background(), Target{
		Options: TargetScanOptions{
			EnabledChecks: map[AnalysisRuleId]bool{
				NoMixedContent: true,
			},
		},
	}, resp)
	noMixedContent := *res[NoMixedContent].DidPass

	if !noMixedContent {
		t.Errorf("Expected %s to pass, but it failed", NoMixedContent)
	}
}
