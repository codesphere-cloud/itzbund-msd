package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
)

func TestSecureSessionCookie(t *testing.T) {
	// start an http server with a secure cookie
	// start a http client that requests the cookie

	table := []struct {
		cookie   http.Cookie
		expected bool
	}{
		{http.Cookie{Name: "session", Value: "1234", Secure: true, Expires: time.Now().Add(1 * time.Hour), HttpOnly: true}, true},
		{http.Cookie{Name: "session", Value: "1234", Secure: false, Expires: time.Now().Add(1 * time.Hour), HttpOnly: true}, false},
		{http.Cookie{Name: "session", Value: "1234", Secure: true, Expires: time.Now().Add(-1 * time.Hour), HttpOnly: false}, false},
		{http.Cookie{Name: "session", Value: "1234", Secure: false, HttpOnly: false}, true}, // no session cookie
	}

	for _, test := range table {
		t.Run("testing: "+test.cookie.String(), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie := test.cookie
				http.SetCookie(w, &cookie)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client := httpclient.NewRedirectAwareHttpClient(nil)

			uri, _ := url.Parse(server.URL)
			target := Target{URL: uri, Options: TargetScanOptions{EnabledChecks: map[AnalysisRuleId]bool{SecureSessionCookies: true}}}

			resp, _ := client.Get(context.Background(), target.URL)

			inspector := NewCookieAnalyzer()

			res, _ := inspector.Analyze(context.Background(), target, resp)

			secureSessionCookie := res[SecureSessionCookies]

			if *secureSessionCookie.DidPass != test.expected {
				t.Error("Expected to pass")
			}
		})
	}
}
