package scanner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/cache"
)

// it does actually issue dns queries!
func TestDomainInspect(t *testing.T) {
	table := []struct {
		domain string
		caa    bool
		dnssec bool
	}{
		{"ozgsec.de", true, true},
		{"google.com", true, false},
		{"microsoft.com", false, false},
	}

	for _, test := range table {
		t.Run("testing: "+test.domain, func(t *testing.T) {
			d := NewDomainAnalyzer()
			uri, _ := url.Parse(fmt.Sprintf("https://%s", test.domain))
			ips, _ := net.LookupIP(uri.Hostname())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, _ := d.Analyze(ctx, Target{
				URL:         uri,
				IPV4Address: selectIPV4(ips),
				IPs:         ips,
				Options: TargetScanOptions{
					CachingLayer: cache.NewDisableCache(),
					EnabledChecks: map[AnalysisRuleId]bool{
						CAA:    true,
						DNSSec: true,
					},
				},
			}, nil)

			dnssec := *result[DNSSec].DidPass
			caa := *result[CAA].DidPass

			if dnssec != test.dnssec {
				t.Error("Expected dnssec to be", test.dnssec, "but was", dnssec)
			}

			if caa != test.caa {
				t.Error("Expected caa to be", test.caa, "but was", caa)
			}
		})
	}
}

func TestIodefPropertyValidation(t *testing.T) {
	table := []struct {
		iodef string
		valid bool
	}{
		{"mailto:", true},
		{"https://", true},
		{"https://example.com", true},
		{"http://example.com/", true},
		{"mailto:example.com", true},
		{";", false},
		{"", false},
	}

	for _, test := range table {
		t.Run("testing: "+test.iodef, func(t *testing.T) {
			result := validateIoDefProperty(test.iodef)

			if result != test.valid {
				t.Error("Expected", test.iodef, "to be", test.valid, "but was", result)
			}
		})
	}
}
