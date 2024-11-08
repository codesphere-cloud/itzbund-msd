package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/cache"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"
)

func TestFailingWith404And500(t *testing.T) {
	for statusCode := range []int{404, 500} {
		t.Run("Failing with status code "+fmt.Sprint(statusCode), func(t *testing.T) {
			// check if the scanner fails with a 404
			inspector := NewOrgAnalyzer()
			// setup a test server
			// check if the scanner fails with a 404
			testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			defer testserver.Close()

			target, _ := url.Parse(testserver.URL)
			// check if the scanner fails with a 404
			res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
				HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // nolint
					},
				}),
				CachingLayer: cache.NewDisableCache(),
				EnabledChecks: map[AnalysisRuleId]bool{
					ResponsibleDisclosure: true,
				},
			}}, nil)
			responsibleDisclosure := res[ResponsibleDisclosure]

			if *responsibleDisclosure.DidPass != false {
				t.Error("Expected to fail")
			}

			if !utils.Includes(responsibleDisclosure.Errors, MissingResponsibleDisclosure) {
				t.Error("Expected to fail with missingResponsibleDisclosureError")
			}

			// check, that the status code is provided as actual value
			if responsibleDisclosure.ActualValue.(map[string]any)["statusCode"] != 404 {
				t.Error("Status code should be provided as actual value")
			}
		})
	}
}

func TestUnscannableIfTimeout(t *testing.T) {
	inspector := NewOrgAnalyzer()
	// setup a test server
	testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer testserver.Close()

	target, _ := url.Parse(testserver.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	// check if the scanner fails with a 404
	res, _ := inspector.Analyze(ctx, Target{URL: target, Options: TargetScanOptions{
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint
			},
		}),
		CachingLayer: cache.NewDisableCache(),
	}}, nil)
	responsibleDisclosure := res[ResponsibleDisclosure]

	if responsibleDisclosure.DidPass != nil {
		t.Error("Expected to be unscannable", responsibleDisclosure.DidPass)
	}
}

func TestSuccessIfContactIsIncluded(t *testing.T) {
	// even allow two contact fields
	for _, text := range []string{"Contact: foo", "Contact:\nContact:"} {
		t.Run("Valid contact: "+text, func(t *testing.T) {
			inspector := NewOrgAnalyzer()
			// setup a test server
			testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// nolint
				w.Write([]byte(text))
			}))
			defer testserver.Close()

			target, _ := url.Parse(testserver.URL)
			res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
				HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // nolint
					},
				}),
				CachingLayer: cache.NewDisableCache(),
				EnabledChecks: map[AnalysisRuleId]bool{
					ResponsibleDisclosure: true,
				},
			}}, nil)
			responsibleDisclosure := res[ResponsibleDisclosure]

			if *responsibleDisclosure.DidPass != false {
				t.Error("Expected to fail")
			}

			if utils.Includes(responsibleDisclosure.Errors, MissingContactField) {
				t.Error("Expected NOT to fail with invalidContactFieldError")
			}
		})
	}
}

func TestFailIfContactMissing(t *testing.T) {
	inspector := NewOrgAnalyzer()
	// setup a test server
	testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// nolint
		w.Write([]byte("Encryption:"))
	}))
	defer testserver.Close()

	target, _ := url.Parse(testserver.URL)
	res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint
			},
		}),
		CachingLayer: cache.NewDisableCache(),
		EnabledChecks: map[AnalysisRuleId]bool{
			ResponsibleDisclosure: true,
		},
	}}, nil)
	responsibleDisclosure := res[ResponsibleDisclosure]

	if *responsibleDisclosure.DidPass != false {
		t.Error("Expected to fail")
	}

	if !utils.Includes(responsibleDisclosure.Errors, MissingContactField) {
		t.Error("Expected to fail with MissingContactField")
	}
}

func TestFailIfExpiresIncludedTwice(t *testing.T) {
	inspector := NewOrgAnalyzer()
	// setup a test server
	testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// nolint
		w.Write([]byte("Expires: 2099-06-29T12:00:00.000Z\nExpires: 2099-06-29T12:00:00.000Z"))
	}))
	defer testserver.Close()

	target, _ := url.Parse(testserver.URL)
	res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint
			},
		}),
		EnabledChecks: map[AnalysisRuleId]bool{
			ResponsibleDisclosure: true,
		},
		CachingLayer: cache.NewDisableCache(),
	}}, nil)
	responsibleDisclosure := res[ResponsibleDisclosure]

	if *responsibleDisclosure.DidPass != false {
		t.Error("Expected to fail")
	}

	if !utils.Includes(responsibleDisclosure.Errors, MissingExpiresField) {
		t.Error("Expected to fail with MissingExpiresField")
	}
}

func TestSuccessIfExpiresInTheFuture(t *testing.T) {
	inspector := NewOrgAnalyzer()
	// setup a test server
	testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// nolint
		w.Write([]byte("Expires: 2099-06-29T12:00:00.000Z"))
	}))
	defer testserver.Close()

	target, _ := url.Parse(testserver.URL)
	res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint
			},
		}),
		EnabledChecks: map[AnalysisRuleId]bool{
			ResponsibleDisclosure: true,
		},
		CachingLayer: cache.NewDisableCache(),
	}}, nil)
	responsibleDisclosure := res[ResponsibleDisclosure]

	if utils.Includes(responsibleDisclosure.Errors, InvalidExpiresField) {
		t.Error("Expected NOT to fail with InvalidExpiresField")
	}
}

func TestFailIfExpiresIsInThePast(t *testing.T) {
	inspector := NewOrgAnalyzer()
	// setup a test server
	testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// nolint
		w.Write([]byte("Expires: 2000-06-29T12:00:00.000Z"))
	}))
	defer testserver.Close()

	target, _ := url.Parse(testserver.URL)
	res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint
			},
		}),
		EnabledChecks: map[AnalysisRuleId]bool{
			ResponsibleDisclosure: true,
		},
		CachingLayer: cache.NewDisableCache(),
	}}, nil)
	responsibleDisclosure := res[ResponsibleDisclosure]

	if *responsibleDisclosure.DidPass != false {
		t.Error("Expected to fail")
	}

	if !utils.Includes(responsibleDisclosure.Errors, Expired) {
		t.Error("Expected to fail with expiredError", responsibleDisclosure.Errors)
	}
}

func TestSuccessForBsiBundSecurityTxt(t *testing.T) {
	inspector := NewOrgAnalyzer()
	// setup a test server
	testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// nolint
		w.Write([]byte(`# For Coordinated Vulnerability Disclosure
        Contact: mailto:vulnerability@bsi.bund.de
        # For BSI related Security Issues
        Contact: mailto:certbund@bsi.bund.de
        Contact: https://www.bsi.bund.de/Security-Contact
        Encryption: https://www.bsi.bund.de/Security-Contact
        Expires: 2099-06-29T12:00:00.000Z
        Preferred-Languages: de, en
        Canonical: https://bsi.bund.de/.well-known/security.txt
        Hiring: https://www.bsi.bund.de/Jobs
        CSAF: https://cert-bund.de/.well-known/csaf/provider-metadata.json`))
	}))
	defer testserver.Close()

	target, _ := url.Parse(testserver.URL)
	res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint
			},
		}),
		EnabledChecks: map[AnalysisRuleId]bool{
			ResponsibleDisclosure: true,
		},
		CachingLayer: cache.NewDisableCache(),
	}}, nil)
	responsibleDisclosure := res[ResponsibleDisclosure]

	if *responsibleDisclosure.DidPass != true {
		t.Error("Expected to pass", responsibleDisclosure.Errors)
	}
}

func TestRecommendedIfIncludesFieldTwice(t *testing.T) {
	table := []struct {
		rec   string
		field string
	}{
		{InvalidEncryptionField, "Encryption"},
		{InvalidCanonicalField, "Canonical"},
		{InvalidPreferredLanguagesField, "Preferred-Languages"},
	}

	for _, test := range table {
		t.Run(test.rec, func(t *testing.T) {
			inspector := NewOrgAnalyzer()
			// setup a test server
			testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// nolint
				w.Write([]byte(test.field + ":\n" + test.field + ":"))
			}))
			defer testserver.Close()

			target, _ := url.Parse(testserver.URL)
			res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
				HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // nolint
					},
				}),
				CachingLayer: cache.NewDisableCache(),
				EnabledChecks: map[AnalysisRuleId]bool{
					ResponsibleDisclosure: true,
				},
			}}, nil)
			responsibleDisclosure := res[ResponsibleDisclosure]

			if !utils.Includes(responsibleDisclosure.Recommendations, test.rec) {
				t.Error("Expected to contain recommendation: ", test.rec)
			}
		})
	}
}

func TestNotRecommendedIfFieldIsIncludedOnce(t *testing.T) {
	table := []struct {
		rec   string
		field string
	}{
		{InvalidEncryptionField, "Encryption"},
		{InvalidCanonicalField, "Canonical"},
		{InvalidPreferredLanguagesField, "Preferred-Languages"},
	}

	for _, test := range table {
		t.Run(test.rec, func(t *testing.T) {
			inspector := NewOrgAnalyzer()
			// setup a test server
			testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// nolint
				w.Write([]byte(test.field + ":\n"))
			}))
			defer testserver.Close()

			target, _ := url.Parse(testserver.URL)
			res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
				CachingLayer: cache.NewDisableCache(),
				HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // nolint
					},
				}),
				EnabledChecks: map[AnalysisRuleId]bool{
					ResponsibleDisclosure: true,
				},
			}}, nil)
			responsibleDisclosure := res[ResponsibleDisclosure]

			if utils.Includes(responsibleDisclosure.Recommendations, test.rec) {
				t.Error("Expected NOT to contain recommendation: ", test.rec)
			}
		})
	}
}

func TestNotRecommendPGPSignatureIfIncluded(t *testing.T) {
	inspector := NewOrgAnalyzer()
	// setup a test server
	testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// nolint
		w.Write([]byte("'--------BEGIN PGP SIGNATURE--------'"))
	}))
	defer testserver.Close()

	target, _ := url.Parse(testserver.URL)
	res, _ := inspector.Analyze(context.Background(), Target{URL: target, Options: TargetScanOptions{
		HttpClient: httpclient.NewRedirectAwareHttpClient(&http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint
			},
		}),
		EnabledChecks: map[AnalysisRuleId]bool{
			ResponsibleDisclosure: true,
		},
		CachingLayer: cache.NewDisableCache(),
	}}, nil)
	responsibleDisclosure := res[ResponsibleDisclosure]

	if utils.Includes(responsibleDisclosure.Recommendations, MissingPGPField) {
		t.Error("Expected NOT to contain recommendation: ", MissingPGPField)
	}
}
