package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestTLSIfReqFails(t *testing.T) {
	// if the http request fails, the tls method should not panic
	res := NewRedirectAwareHttpClient(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	defer server.Close()

	uri, _ := url.Parse(server.URL)
	resp, _ := res.Get(context.Background(), uri)

	if resp.TLS() != nil {
		t.Error("Expected TLS to be nil")
	}
}

func TestNoPanicIfTimeout(t *testing.T) {
	// if the http request fails, the tls method should not panic
	res := NewRedirectAwareHttpClient(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())

	cancel()

	uri, _ := url.Parse(server.URL)
	resp, _ := res.Get(ctx, uri)

	// it should return nil instead of panic
	if resp.InitialResponse() != nil {
		t.Error("Expected TLS to be nil")
	}
}
