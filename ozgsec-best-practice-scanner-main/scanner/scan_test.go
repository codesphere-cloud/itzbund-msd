package scanner

import (
	"context"
	"net/http"
	"testing"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/cache"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/tlsclient"
)

// we do snapshot testing - those tests are brittle and subject to change often - but they are a good way to detect regressions
// date: 2023-05-02
var testTargets = map[string]ScanResponse{
	/*"www.google.com": {
		Result: ScanSuccess{
			ResponsibleDisclosure:    NewAnalysisResult(Failure, nil, nil, nil),
			TLS13:                    NewAnalysisResult(Success, nil, nil, nil),
			DeprecatedTLSDeactivated: NewAnalysisResult(Failure, nil, nil, nil),
			HSTS:                     NewAnalysisResult(Success, nil, nil, nil),
			DNSSec:                   NewAnalysisResult(Failure, nil, nil, nil),
			RPKI:                     NewAnalysisResult(Success, nil, nil, nil),
		},
	},
	"neuland-homeland.de": {
		Result: ScanSuccess{
			ResponsibleDisclosure:    NewAnalysisResult(Success, nil, nil, nil),
			TLS13:                    NewAnalysisResult(Success, nil, nil, nil),
			DeprecatedTLSDeactivated: NewAnalysisResult(Success, nil, nil, nil),
			HSTS:                     NewAnalysisResult(Success, nil, nil, nil),
			DNSSec:                   NewAnalysisResult(Failure, nil, nil, nil),
			RPKI:                     NewAnalysisResult(Success, nil, nil, nil),
		},
	},
	"bmi.bund.de": {
		Result: ScanSuccess{
			ResponsibleDisclosure:    NewAnalysisResult(Success, nil, nil, nil),
			TLS13:                    NewAnalysisResult(Success, nil, nil, nil),
			DeprecatedTLSDeactivated: NewAnalysisResult(Unknown, nil, nil, nil),
			HSTS:                     NewAnalysisResult(Success, nil, nil, nil),
			DNSSec:                   NewAnalysisResult(Success, nil, nil, nil),
			RPKI:                     NewAnalysisResult(Success, nil, nil, nil),
		},
	},
	"em-hoettche.de": {
		Result: ScanSuccess{
			ResponsibleDisclosure:    NewAnalysisResult(Failure, nil, nil, nil),
			TLS13:                    NewAnalysisResult(Failure, nil, nil, nil),
			DeprecatedTLSDeactivated: NewAnalysisResult(Success, nil, nil, nil),
			HSTS:                     NewAnalysisResult(Failure, nil, nil, nil),
			DNSSec:                   NewAnalysisResult(Failure, nil, nil, nil),
			RPKI:                     NewAnalysisResult(Success, nil, nil, nil),
		},
	},*/
	"www.bonnorange.de": {
		Result: ScanSuccess{
			ResponsibleDisclosure:    NewAnalysisResult(Failure, nil, nil, nil, 0),
			TLS13:                    NewAnalysisResult(Success, nil, nil, nil, 0),
			DeprecatedTLSDeactivated: NewAnalysisResult(Success, nil, nil, nil, 0),
			HSTS:                     NewAnalysisResult(Failure, nil, nil, nil, 0),
			DNSSec:                   NewAnalysisResult(Failure, nil, nil, nil, 0),
			RPKI:                     NewAnalysisResult(Success, nil, nil, nil, 0),
		},
	},
	/*"www.bsi.bund.de": {
		Result: ScanSuccess{
			ResponsibleDisclosure:    NewAnalysisResult(Success, nil, nil, nil),
			TLS13:                    NewAnalysisResult(Success, nil, nil, nil),
			DeprecatedTLSDeactivated: NewAnalysisResult(Success, nil, nil, nil),
			HSTS:                     NewAnalysisResult(Success, nil, nil, nil),
			DNSSec:                   NewAnalysisResult(Success, nil, nil, nil),
			RPKI:                     NewAnalysisResult(Success, nil, nil, nil),
		},
	},*/
}

var allChecksEnabled = map[AnalysisRuleId]bool{
	ResponsibleDisclosure:    true,
	TLS13:                    true,
	DeprecatedTLSDeactivated: true,
	HSTS:                     true,
	DNSSec:                   true,
	RPKI:                     true,
}

func TestScan(t *testing.T) {
	for target, expectedResult := range testTargets {

		context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		scanner := NewScanner()
		res := scanner.Scan(context, target, TargetScanOptions{
			CachingLayer: cache.NewDisableCache(),
			HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
				IdleConnTimeout: 5 * time.Second,
			}),
			TlsClient:     tlsclient.NewDefaultClient(),
			EnabledChecks: allChecksEnabled,
		})

		for key, expected := range expectedResult.ScanSuccess() {
			if expected.IsSuccess() != res.ScanSuccess()[key].IsSuccess() {
				t.Errorf("For %v (scan: %v), expected %v, got %v", target, key, expected.IsSuccess(), res.ScanSuccess()[key].IsSuccess())
			}
			if expected.IsUnknown() != res.ScanSuccess()[key].IsUnknown() {
				println(res.UnscannableKeys())
				t.Errorf("For %v (scan: %v), expected IsUnknown() to be %v, but got %v", target, key, expected.IsUnknown(), res.ScanSuccess()[key].IsUnknown())
			}
		}
	}
}

func TestScanCaching(t *testing.T) {
	memoryCache := cache.NewMemoryCache[any]()

	// set everything to false - just to make sure we can detect a cache hit
	cached := map[AnalysisRuleId]AnalysisResult{
		CertificateTransparency:  NewAnalysisResult(Failure, nil, nil, nil, 0),
		NotRevoked:               NewAnalysisResult(Failure, nil, nil, nil, 0),
		ValidCertificate:         NewAnalysisResult(Failure, nil, nil, nil, 0),
		ValidCertificateChain:    NewAnalysisResult(Failure, nil, nil, nil, 0),
		MatchesHostname:          NewAnalysisResult(Failure, nil, nil, nil, 0),
		StrongPrivateKey:         NewAnalysisResult(Failure, nil, nil, nil, 0),
		StrongSignatureAlgorithm: NewAnalysisResult(Failure, nil, nil, nil, 0),

		DNSSec: NewAnalysisResult(Failure, nil, nil, nil, 0),

		ResponsibleDisclosure: NewAnalysisResult(Failure, nil, nil, nil, 0),
	}

	ctx := context.Background()

	// nolint
	memoryCache.Set(ctx, "www.neuland-homeland.de", cached, 1*time.Hour)

	scanner := NewScanner()
	res := scanner.Scan(ctx, "www.neuland-homeland.de", TargetScanOptions{
		CachingLayer: memoryCache,
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			IdleConnTimeout: 5 * time.Second,
		}),
		TlsClient: tlsclient.NewDefaultClient(),
	})

	if res.ScanSuccess()[ResponsibleDisclosure].IsSuccess() {
		t.Errorf("Expected cache hit for ResponsibleDisclosure")
	}

	if res.ScanSuccess()[DNSSec].IsSuccess() {
		t.Errorf("Expected cache hit for DNSSec")
	}

	if res.ScanSuccess()[CertificateTransparency].IsSuccess() {
		t.Errorf("Expected cache hit for CertificateTransparency")
	}
}
