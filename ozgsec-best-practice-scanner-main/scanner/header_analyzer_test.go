package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

type tableTest struct {
	expectedErrorSubset []string
	expectedRecSubset   []string
	header              map[string]string
	t                   AnalysisRuleId
}

func buildForAll(blueprint tableTest, headers []AnalysisRuleId) []tableTest {
	res := make([]tableTest, len(headers))
	for i, h := range headers {
		res[i] = tableTest{
			expectedErrorSubset: blueprint.expectedErrorSubset,
			expectedRecSubset:   blueprint.expectedRecSubset,
			header:              blueprint.header,
			t:                   h,
		}
	}
	return res
}
func TestHeaderAnalyzer(t *testing.T) {

	table := []tableTest{
		{
			expectedErrorSubset: []string{MissingMaxAge},
			expectedRecSubset:   []string{},
			header: map[string]string{
				"Strict-Transport-Security": "includeSubDomains",
			},
			t: HSTS,
		},
		{
			expectedRecSubset:   []string{MissingIncludeSubDomains},
			expectedErrorSubset: []string{},
			header: map[string]string{
				"Strict-Transport-Security": "max-age=31536000",
			},
			t: HSTS,
		},
		{
			expectedErrorSubset: []string{NotDenyOrSameOrigin},
			expectedRecSubset:   []string{},
			header: map[string]string{
				"X-Frame-Options": "ALLOW-FROM https://example.com/",
			},
			t: XFrameOptions,
		},
		{
			expectedErrorSubset: []string{},
			expectedRecSubset:   []string{},
			header: map[string]string{
				"X-Frame-Options": "DENY",
			},
			t: XFrameOptions,
		},
		{
			expectedErrorSubset: []string{NotEnabled, MissingModeBlock},
			expectedRecSubset:   []string{},
			header: map[string]string{
				"X-XSS-Protection": "0",
			},
			t: XSSProtection,
		},
		{
			expectedErrorSubset: []string{MissingModeBlock},
			expectedRecSubset:   []string{},
			header: map[string]string{
				"X-XSS-Protection": "1",
			},
			t: XSSProtection,
		},
		{
			expectedRecSubset:   []string{MissingDefaultSrcWithSelf, MissingStyleSrc, MissingImgSrc},
			expectedErrorSubset: []string{},
			header: map[string]string{
				"Content-Security-Policy": "script-src 'self' https://apis.google.com",
			},
			t: ContentSecurityPolicy,
		},

		{
			expectedErrorSubset: []string{NotNoSniff},
			expectedRecSubset:   []string{},
			header: map[string]string{
				"X-Content-Type-Options": "",
			},
			t: ContentTypeOptions,
		},
	}

	// build the missing header test for all headers
	table = append(table, buildForAll(tableTest{
		expectedErrorSubset: []string{MissingHeader},
		expectedRecSubset:   []string{},
		header:              map[string]string{},
	}, []AnalysisRuleId{
		HSTS,
		ContentSecurityPolicy,
		XFrameOptions,
		XSSProtection,
		ContentTypeOptions,
	})...)

	for _, test := range table {
		t.Run(fmt.Sprintf("%v", test.t), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range test.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			inspector := NewHeaderAnalyzer()
			client := httpclient.NewRedirectAwareHttpClient(nil)

			target, _ := url.Parse(server.URL)

			resp, _ := client.Get(context.Background(), target)

			res, _ := inspector.Analyze(context.Background(), Target{
				Options: TargetScanOptions{
					EnabledChecks: map[AnalysisRuleId]bool{
						HSTS:                  true,
						XFrameOptions:         true,
						XSSProtection:         true,
						ContentSecurityPolicy: true,
						ContentTypeOptions:    true,
					},
				},
			}, resp)

			actual := res[test.t]

			if !utils.IncludesSubset(actual.Errors, test.expectedErrorSubset) {
				t.Error("Expected" + fmt.Sprintf("%v", test.expectedErrorSubset) + "to be in" + fmt.Sprintf("%v", actual.Errors))
			}

			if !utils.IncludesSubset(actual.Recommendations, test.expectedRecSubset) {
				t.Error("Expected" + fmt.Sprintf("%v", test.expectedRecSubset) + "to be in" + fmt.Sprintf("%v", actual.Recommendations))
			}
		})
	}
}
