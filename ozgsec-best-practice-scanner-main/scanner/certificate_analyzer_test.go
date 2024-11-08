package scanner

import (
	"context"
	"net/http"
	"testing"
)

func TestIsNotRevoked(t *testing.T) {
	res, err := http.Get("https://opencode.de")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	result := isNotRevoked(context.Background(), res.TLS.PeerCertificates)

	if !*result.DidPass {
		t.Errorf("Expected success, got %v", result)
	}
}
