package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/cache"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
)

// it does actually call the ripe api!
func TestNetworkInspect(t *testing.T) {
	table := []struct {
		domain string
		ipv6   bool
		rpki   bool
	}{
		{"ozgsec.de", true, true},
		{"bund.de", false, true},
	}

	for _, test := range table {
		t.Run("testing: "+test.domain, func(t *testing.T) {
			d := NewNetworkAnalyzer(httpclient.NewDefaultClient())

			// resolve all ips for the domain
			ips, err := net.LookupIP(test.domain)
			if err != nil {
				t.Error(err)
			}
			target := Target{
				IPs: ips,
				Options: TargetScanOptions{
					CachingLayer: cache.NewDisableCache(),
					EnabledChecks: map[AnalysisRuleId]bool{
						IPv6: true,
						RPKI: true,
					},
				},
			}

			result, _ := d.Analyze(context.Background(), target, nil)

			ipv6 := *result[IPv6].DidPass
			rpki := *result[RPKI].DidPass

			if ipv6 != test.ipv6 {
				t.Error("Expected ipv6 to be", test.ipv6)
			}

			if rpki != test.rpki {
				t.Error("Expected rpki to be", test.rpki, "but was", rpki)
			}
		})
	}
}

// Ref: https://gitlab.com/ozg-security/ozgsec-security-quick-test/-/issues/113
func TestTheSamePrefixIsOnlyReturnedOnce(t *testing.T) {
	d := NewNetworkAnalyzer(httpclient.NewDefaultClient())

	// resolve all ips for the domain
	ips, err := net.LookupIP("www.bundesimmobilien.de")
	if err != nil {
		t.Error(err)
	}
	target := Target{
		IPs: ips,
		Options: TargetScanOptions{
			CachingLayer: cache.NewDisableCache(),
			EnabledChecks: map[AnalysisRuleId]bool{
				RPKI: true,
			},
		},
	}

	result, _ := d.Analyze(context.Background(), target, nil)

	rpkiResults := result[RPKI].ActualValue.([]rpkiResult)

	// check if the same prefix is only returned once
	prefixes := make(map[string]bool)
	for _, rpkiResult := range rpkiResults {
		if _, ok := prefixes[rpkiResult.Prefix]; ok {
			t.Error("The same prefix is returned twice")
		}
		prefixes[rpkiResult.Prefix] = true
	}
}

func TestRPKICaching(t *testing.T) {
	inspector := NewNetworkAnalyzer(httpclient.NewDefaultClient())

	ips := []net.IP{net.IPv4(127, 0, 0, 1)}
	memoryCache := cache.NewMemoryCache[any]()

	cachedValue := rpkiResult{
		IsValid: true,
		Asn:     123,
	}

	// the time does not matter
	memoryCache.Set(context.Background(), "127.0.0.1", cachedValue, 1*time.Hour) // nolint // will never fail

	target := Target{
		IPs: ips,
		Options: TargetScanOptions{
			CachingLayer: memoryCache,
			EnabledChecks: map[AnalysisRuleId]bool{
				RPKI: true,
			},
		},
	}

	result, _ := inspector.Analyze(context.Background(), target, nil)

	rpkiResults := result[RPKI].ActualValue.([]rpkiResult)

	if len(rpkiResults) != 1 {
		t.Error("Expected one result but got", len(rpkiResults))
	}

	if !rpkiResults[0].IsValid {
		t.Error("Expected the cached result to be valid")
	}

	if rpkiResults[0].Asn != 123 {
		t.Error("Expected the cached result to have asn 123 but got", rpkiResults[0].Asn)
	}
}
