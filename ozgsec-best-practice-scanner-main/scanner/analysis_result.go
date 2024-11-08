package scanner

import (
	"encoding/json"
	"fmt"
	"time"
)

type AnalysisRuleId string

type DidPass *bool

var (
	Success DidPass = ptr(true)
	Failure DidPass = ptr(false)
	Unknown DidPass = nil
)

func interpret(didPass bool, err error) DidPass {
	if err != nil {
		return Unknown
	}
	if didPass {
		return Success
	}
	return Failure
}

func ptr[T any](input T) *T {
	return &input
}

const (
	ProvidesEnglishWebsiteVersion AnalysisRuleId = "providesEnglishWebsiteVersion"

	DKIM     AnalysisRuleId = "dkim"
	DMARC    AnalysisRuleId = "dmarc"
	SPF      AnalysisRuleId = "spf"
	STARTTLS AnalysisRuleId = "starttls"
	DANE     AnalysisRuleId = "dane"

	SubResourceIntegrity AnalysisRuleId = "subResourceIntegrity"
	NoMixedContent       AnalysisRuleId = "noMixedContent"

	ResponsibleDisclosure AnalysisRuleId = "responsibleDisclosure"
	DNSSec                AnalysisRuleId = "dnsSec"
	CAA                   AnalysisRuleId = "caa"

	IPv6 AnalysisRuleId = "ipv6"
	RPKI AnalysisRuleId = "rpki"

	HTTP                 AnalysisRuleId = "http"
	HTTP308              AnalysisRuleId = "http308"
	HTTPRedirectsToHttps AnalysisRuleId = "httpRedirectsToHttps"

	HTTPS                 AnalysisRuleId = "https"
	HSTS                  AnalysisRuleId = "hsts"
	HSTSPreloaded         AnalysisRuleId = "hstsPreloaded"
	ContentSecurityPolicy AnalysisRuleId = "contentSecurityPolicy"
	XFrameOptions         AnalysisRuleId = "xFrameOptions"
	XSSProtection         AnalysisRuleId = "xssProtection"
	ContentTypeOptions    AnalysisRuleId = "contentTypeOptions"

	SecureSessionCookies     AnalysisRuleId = "secureSessionCookies"
	TLS12                    AnalysisRuleId = "tlsv1_2"
	TLS13                    AnalysisRuleId = "tlsv1_3"
	DeprecatedTLSDeactivated AnalysisRuleId = "deprecatedTLSDeactivated"

	StrongKeyExchange  AnalysisRuleId = "strongKeyExchange"
	StrongCipherSuites AnalysisRuleId = "strongCipherSuites"

	ValidCertificate         AnalysisRuleId = "validCertificate"
	StrongPrivateKey         AnalysisRuleId = "strongPrivateKey"
	StrongSignatureAlgorithm AnalysisRuleId = "strongSignatureAlgorithm"
	MatchesHostname          AnalysisRuleId = "matchesHostname"
	NotRevoked               AnalysisRuleId = "notRevoked"
	CertificateTransparency  AnalysisRuleId = "certificateTransparency"
	ValidCertificateChain    AnalysisRuleId = "validCertificateChain"
)

var HttpBasedScans = []AnalysisRuleId{
	HTTP,
	HTTP308,
	HTTPRedirectsToHttps,

	HTTPS,
	HSTS,
	HSTSPreloaded,
	ContentSecurityPolicy,
	XFrameOptions,
	XSSProtection,
	ContentTypeOptions,

	SecureSessionCookies,

	SubResourceIntegrity,
	NoMixedContent,
}

var AllChecks = []AnalysisRuleId{
	ProvidesEnglishWebsiteVersion,
	HSTS,
	HSTSPreloaded,
	ContentSecurityPolicy,
	XFrameOptions,
	XSSProtection,
	ContentTypeOptions,
	SubResourceIntegrity,
	NoMixedContent,
	ResponsibleDisclosure,
	DNSSec,
	CAA,
	IPv6,
	RPKI,
	HTTP,
	HTTP308,
	HTTPRedirectsToHttps,
	HTTPS,
	StrongKeyExchange,
	StrongCipherSuites,
	TLS12,
	TLS13,
	DeprecatedTLSDeactivated,
	ValidCertificate,
	StrongPrivateKey,
	StrongSignatureAlgorithm,
	MatchesHostname,
	NotRevoked,
	CertificateTransparency,
	ValidCertificateChain,
	DKIM,
	DMARC,
	SPF,
	STARTTLS,
	DANE,
}

type AnalysisResult struct {
	DidPass         *bool    `json:"didPass"`
	ActualValue     any      `json:"actualValue"`
	Errors          []string `json:"errors"`
	Recommendations []string `json:"recommendations"`
	Duration        time.Duration
}

func (r AnalysisResult) MarshalJSON() ([]byte, error) {
	res := map[string]interface{}{
		"didPass":         r.DidPass,
		"errors":          r.Errors,
		"recommendations": r.Recommendations,
		"actualValue":     r.ActualValue,
	}
	if r.ActualValue == nil {
		res["actualValue"] = map[string]interface{}{}
	}
	if r.Errors == nil {
		res["errors"] = []string{}
	}
	if r.Recommendations == nil {
		res["recommendations"] = []string{}
	}
	res["durationMS"] = r.Duration.Milliseconds()
	return json.Marshal(res)
}

func (r AnalysisResult) IsSuccess() bool {
	return r.DidPass != nil && *r.DidPass
}

func (r AnalysisResult) IsError() bool {
	return r.DidPass != nil && !*r.DidPass
}

func (r AnalysisResult) IsUnknown() bool {
	return r.DidPass == nil
}

func NewAnalysisResult(didPass *bool, actualVal any, errors []string, recommendations []string, duration time.Duration) AnalysisResult {
	return AnalysisResult{
		DidPass:         didPass,
		ActualValue:     actualVal,
		Errors:          errors,
		Recommendations: recommendations,
		Duration:        duration,
	}
}

func cacheSerializerFactory[T any](fn func(data any) T) func(data any) T {
	return func(data any) T {
		// check if data is already the correct interface
		// this happens if a caching layer is actually returning from memory instead of json
		if res, ok := data.(T); ok {
			return res
		}
		return fn(data)
	}
}

var newAggregatedAnalysisResultFromJSON = cacheSerializerFactory(func(data any) map[AnalysisRuleId]AnalysisResult {
	// convert to json map
	jsonMap := data.(map[string]interface{})

	// convert to map[AnalysisType]AnalysisResult
	res := make(map[AnalysisRuleId]AnalysisResult)
	for k, v := range jsonMap {
		// convert to json map
		jsonMap := v.(map[string]interface{})

		var errors []string
		if jsonMap["errors"] != nil {
			// convert to AnalysisResult
			errs := jsonMap["errors"].([]interface{})
			errors := make([]string, len(errs))
			for i, err := range errs {
				errors[i] = err.(string)
			}
		} else {
			errors = []string{}
		}

		var recommendations []string
		if jsonMap["recommendations"] != nil {
			// convert to AnalysisResult
			recs := jsonMap["recommendations"].([]interface{})
			recommendations := make([]string, len(recs))
			for i, rec := range recs {
				recommendations[i] = rec.(string)
			}
		} else {
			recommendations = []string{}
		}

		// check if didPass is nil
		var didPass *bool
		if jsonMap["didPass"] == nil {
			didPass = nil
		} else {
			didPass = ptr(jsonMap["didPass"].(bool))
		}
		analysisResult := AnalysisResult{
			DidPass:         didPass,
			ActualValue:     jsonMap["actualValue"],
			Errors:          errors,
			Recommendations: recommendations,
		}
		// add to map
		res[AnalysisRuleId(k)] = analysisResult
	}
	return res
})

// will return an error, if the provided analysis types do not exist.
func getFromCache(data any, types []AnalysisRuleId) (map[AnalysisRuleId]AnalysisResult, error) {
	cached := newAggregatedAnalysisResultFromJSON(data)
	var res = make(map[AnalysisRuleId]AnalysisResult)
	// check if all analysis types exist
	for _, t := range types {
		if el, ok := cached[t]; ok {
			res[t] = el
		} else {
			return nil, fmt.Errorf("analysis type %s does not exist", t)
		}
	}
	return res, nil
}
