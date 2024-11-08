package transformer

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/sarif"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/scanner"
)

var mapping = map[scanner.AnalysisRuleId]sarif.ReportingDescriptor{
	scanner.ProvidesEnglishWebsiteVersion: {
		Id:   string(scanner.ProvidesEnglishWebsiteVersion),
		Name: ptr("Provides English Website Version"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Uses Heuristic to determine the language of the website. The check looks at the body and extracts the text content. It applies a language prediction model.",
		},
	},
	scanner.STARTTLS: {
		Id:   string(scanner.STARTTLS),
		Name: ptr("STARTTLS"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the target supports STARTTLS. STARTTLS is a way to take an existing insecure connection and upgrade it to a secure connection using SSL/TLS.",
		},
	},
	scanner.DKIM: {
		Id:   string(scanner.DKIM),
		Name: ptr("DKIM"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the domain has a DKIM record. RFC6376 (https://www.rfc-editor.org/rfc/rfc6376).",
		},
	},
	scanner.DMARC: {
		Id:   string(scanner.DMARC),
		Name: ptr("DMARC"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the domain has a DMARC record. RFC7489 (https://www.rfc-editor.org/rfc/rfc7489).",
		},
	},
	scanner.SPF: {
		Id:   string(scanner.SPF),
		Name: ptr("SPF"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the domain has a SPF record. RFC7208 (https://www.rfc-editor.org/rfc/rfc7208).",
		},
	},
	scanner.DANE: {
		Id:   string(scanner.DANE),
		Name: ptr("DANE"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the domain has a DANE record. RFC6698 (https://www.rfc-editor.org/rfc/rfc6698).",
		},
	},
	scanner.ValidCertificate: {
		Id:   string(scanner.ValidCertificate),
		Name: ptr("Valid Certificate"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the certificate of a website is valid. A certificate is considered valid if it is not expired and if it is yet valid.",
		},
	},
	scanner.ValidCertificateChain: {
		Id:   string(scanner.ValidCertificateChain),
		Name: ptr("Signing-Chain of the certificate is valid"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the certificate chain is valid. The check is conform to RFC5280 (https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)",
		},
	},
	scanner.MatchesHostname: {
		Id:   string(scanner.MatchesHostname),
		Name: ptr("Certificate matches hostname of the website"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the certificate matches the hostname of the website.",
		},
	},
	scanner.StrongPrivateKey: {
		Id:   string(scanner.StrongPrivateKey),
		Name: ptr("Certificate is signed using a strong private key"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the certificate is signed using a strong private key. A strong private key is a private RSA key with a bit length of at least 2048 or a DSA key.",
		},
	},
	scanner.NotRevoked: {
		Id:   string(scanner.NotRevoked),
		Name: ptr("Certificate is not revoked"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the certificate is not revoked. The check is conform to RFC5280 (https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.6)",
		},
	},
	scanner.StrongSignatureAlgorithm: {
		Id:   string(scanner.StrongSignatureAlgorithm),
		Name: ptr("Certificate is not signed using a weak signature algorithm"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the certificate is not signed using a weak signature algorithm. The check is conform to https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm",
		},
	},
	scanner.CertificateTransparency: {
		Id:   string(scanner.CertificateTransparency),
		Name: ptr("Certificate Transparency"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the certificate uses certificate transparency. RFC6962 (https://www.rfc-editor.org/rfc/rfc6962) defines a certificate transparency log as a log which contains all certificates which are issued by a CA. This check does not check if the certificate is in the log, but if the certificate contains the certificate transparency extension, signed certificate timestamps or a OCSP Response.",
		},
	},
	scanner.SubResourceIntegrity: {
		Id:   string(scanner.SubResourceIntegrity),
		Name: ptr("Subresource Integrity"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if Subresource Integrity (SRI) (https://www.w3.org/TR/SRI/) integrity is used on the webpage.",
		},
	},
	scanner.NoMixedContent: {
		Id:   string(scanner.NoMixedContent),
		Name: ptr("No Mixed Content"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if there is mixed content on the webpage (https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content).",
		},
	},
	scanner.SecureSessionCookies: {
		Id:   string(scanner.SecureSessionCookies),
		Name: ptr("Secure Session Cookies"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if all session cookies are secure and http only. The check inspects the Set-Cookie Header. If Expires attribute is set to 0, the cookie is NOT considered a session cookie.",
		},
	},
	scanner.DNSSec: {
		Id:   string(scanner.DNSSec),
		Name: ptr("DNSSEC"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the domain supports DNSSEC. RFC9364 (https://www.rfc-editor.org/rfc/rfc9364).",
		},
	},
	scanner.CAA: {
		Id:   string(scanner.CAA),
		Name: ptr("CAA"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the domain supports CAA. RFC8659 (https://www.rfc-editor.org/rfc/rfc8659.html).",
		},
	},
	scanner.HTTPS: {
		Id:   string(scanner.HTTPS),
		Name: ptr("HTTPS"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the website is served over HTTPS. It will will follow redirects to HTTPS.",
		},
	},
	scanner.HSTS: {
		Id:   string(scanner.HSTS),
		Name: ptr("HSTS"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the website has HSTS enabled. Max-Age is required, includeSubDomains recommended. RFC6797 (https://www.rfc-editor.org/rfc/rfc6797).",
		},
	},
	scanner.XFrameOptions: {
		Id:   string(scanner.XFrameOptions),
		Name: ptr("X-Frame-Options"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the website has X-Frame-Options enabled. DENY or SAMEORIGIN are both valid configuration. RFC7034 (https://www.rfc-editor.org/rfc/rfc7034).",
		},
	},
	scanner.XSSProtection: {
		Id:   string(scanner.XSSProtection),
		Name: ptr("X-XSS-Protection"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the website has X-XSS-Protection enabled. Needs to have a value of 1 and the mode needs to be set to 'block'. RFC7034 (https://www.rfc-editor.org/rfc/rfc7034).",
		},
	},
	scanner.HSTSPreloaded: {
		Id:   string(scanner.HSTSPreloaded),
		Name: ptr("HSTS Preloaded"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the website HSTS-Header enabled preloading. RFC6797 (https://www.rfc-editor.org/rfc/rfc6797).",
		},
	},
	scanner.ContentTypeOptions: {
		Id:   string(scanner.ContentTypeOptions),
		Name: ptr("X-Content-Type-Options"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the website has X-Content-Type-Options enabled. The Value needs to be set to 'nosniff'.",
		},
	},
	scanner.ContentSecurityPolicy: {
		Id:   string(scanner.ContentSecurityPolicy),
		Name: ptr("Content Security Policy"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the website has a Content Security Policy (CSP) enabled. The Check does not validate the configuration since there is no standard. The check adds recommendations if the default-src is not set to 'self' and if script-src, style-src or img-src are missing.",
		},
	},
	scanner.HTTP: {
		Id:   string(scanner.HTTP),
		Name: ptr("HTTP"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the server responds to HTTP requests. If the server responds with a 5xx status code, the check is considered a failure.",
		},
	},
	scanner.HTTP308: {
		Id:   string(scanner.HTTP308),
		Name: ptr("HTTP 308"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the server responds the HTTP-GET request with a 308 (Permanent Redirect) status code.",
		},
	},
	scanner.HTTPRedirectsToHttps: {
		Id:   string(scanner.HTTPRedirectsToHttps),
		Name: ptr("HTTP redirects to HTTPS"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks, if the website redirects to an https site, if an http request is send to it.",
		},
	},
	scanner.RPKI: {
		Id:   string(scanner.RPKI),
		Name: ptr("RPKI"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the target supports RPKI. If the target supports RPKI, it checks if the RPKI status is valid for all derived prefixes. If a domain has multiple IP addresses, the check is considered a success if all IP addresses have a valid RPKI status.",
		},
	},
	scanner.IPv6: {
		Id:   string(scanner.IPv6),
		Name: ptr("IPv6"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks if the target supports IPv6 (AAAA record is present).",
		},
	},
	scanner.ResponsibleDisclosure: {
		Id:   string(scanner.ResponsibleDisclosure),
		Name: ptr("Responsible Disclosure"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks, if the file /.well-known/security.txt is present, served over https, is served as a text/plain file, and if it contains the required fields. The required fields are: Contact, Expires. The recommended fields are: Encryption, Canonical, Preferred-Languages. The file is also checked for a PGP signature.",
		},
	},
	scanner.TLS12: {
		Id:   string(scanner.TLS12),
		Name: ptr("TLS 1.2 supported"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "TLS 1.2 is supported",
		},
	},
	scanner.TLS13: {
		Id:   string(scanner.TLS13),
		Name: ptr("TLS 1.3 supported"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "TLS 1.3 is supported",
		},
	},
	scanner.DeprecatedTLSDeactivated: {
		Id:   string(scanner.DeprecatedTLSDeactivated),
		Name: ptr("Deprecated TLS deactivated"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Deprecated TLS protocols (TLSv1.0, TLSv1.1) are deactivated",
		},
	},
	scanner.StrongKeyExchange: {
		Id:   string(scanner.StrongKeyExchange),
		Name: ptr("Strong key exchange"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "NOT IMPLEMENTED: Strong key exchange algorithms are used",
		},
	},
	scanner.StrongCipherSuites: {
		Id:   string(scanner.StrongCipherSuites),
		Name: ptr("Strong cipher suites"),
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Checks, if strong cipher suites are used during the TLS handshake. As Strong cipher suites we consider the recommended cipher suites from mozilla: https://wiki.mozilla.org/Security/Server_Side_TLS",
		},
	},
}

func getRules() []sarif.ReportingDescriptor {
	var res = make([]sarif.ReportingDescriptor, len(mapping))
	var i = 0
	for _, rule := range mapping {
		res[i] = rule
		i++
	}

	return res
}

var rulesArr = getRules()

func ptr[T any](input T) *T {
	return &input
}

func didPassToKind(didPass scanner.DidPass) sarif.ResultKind {
	if didPass == nil {
		return sarif.ResultKindNotApplicable
	} else if *didPass {
		return sarif.ResultKindPass
	}
	return sarif.ResultKindFail
}

func genericMessageString(ruleId scanner.AnalysisRuleId, didPass scanner.DidPass) string {
	if didPass == nil {
		return fmt.Sprintf("the test for rule %s was not applicable", ruleId)
	} else if *didPass {
		return fmt.Sprintf("the test for rule %s was successful", ruleId)
	}
	return fmt.Sprintf("the test for rule %s failed", ruleId)
}

func findRuleIndex(ruleId scanner.AnalysisRuleId) int {
	for i, rule := range rulesArr {
		if rule.Id == string(ruleId) {
			return i
		}
	}
	return -1
}

func transformToSarifResult(results map[scanner.AnalysisRuleId]scanner.AnalysisResult) []sarif.Result {
	var res = make([]sarif.Result, len(results))

	var i = 0
	for ruleId, result := range results {
		// find the rule which belongs to the result
		ruleIndex := findRuleIndex(ruleId)

		if ruleIndex == -1 {
			panic(fmt.Sprintf("rule %s not found", ruleId))
		}
		// check if errors and recommendations are set
		var errors, recommendations []string
		if result.Errors != nil {
			errors = result.Errors
		} else {
			errors = []string{}
		}

		if result.Recommendations != nil {
			recommendations = result.Recommendations
		} else {
			recommendations = []string{}
		}

		res[i] = sarif.Result{
			RuleId:    ptr(string(ruleId)),
			RuleIndex: ruleIndex,
			Kind:      didPassToKind(result.DidPass),
			Message: sarif.Message{
				Text: ptr(genericMessageString(ruleId, result.DidPass)),
			},
			Properties: sarif.PropertyBag{
				"errorIds":          errors,
				"recommendationIds": recommendations,
				"actualValue":       result.ActualValue,
				"durationMs":        result.Duration.Milliseconds(),
			},
		}
		i++
	}
	// sort the results by ruleIndex
	sort.Slice(res, func(i, j int) bool {
		return res[i].RuleIndex < res[j].RuleIndex
	})
	return res
}

type sarifTransformer struct {
}

func NewSarifTransformer() sarifTransformer {
	return sarifTransformer{}
}

func (s sarifTransformer) Transform(input scanner.ScanResponse) ([]byte, error) {
	sarifReport := sarif.Sarif210Json{
		Version: "2.1.0",
		Schema:  ptr("https://json.schemastore.org/sarif-2.1.0.json"),
		Runs: []sarif.Run{{
			Tool: sarif.Tool{
				Driver: sarif.ToolComponent{
					Name:    "ozgsec-scanner",
					Version: ptr(os.Getenv("VERSION")),
					Rules:   rulesArr,
					Properties: sarif.PropertyBag{
						"scannerIp": input.ScannerIP,
					},
				},
			},
			Properties: sarif.PropertyBag{
				"target":    input.Target,
				"sut":       input.SUT,
				"ipAddress": input.IpAddress,
			},
		}},
	}

	// check if there are any results
	if input.IsSuccess() {
		sarifReport.Runs[0].Results = transformToSarifResult(input.Result.(map[scanner.AnalysisRuleId]scanner.AnalysisResult))
		sarifReport.Runs[0].Invocations = []sarif.Invocation{{
			ExecutionSuccessful: true,
			ExitCode:            ptr(0),
			ExitCodeDescription: ptr("success"),
			StartTimeUtc:        ptr(time.Unix((input.Timestamp)/1000, 0).UTC().Format(time.RFC3339)),
			EndTimeUtc:          ptr(time.Unix((input.Timestamp+input.Duration)/1000, 0).UTC().Format(time.RFC3339)),
		}}
	} else {
		sarifReport.Runs[0].Results = []sarif.Result{}
		sarifReport.Runs[0].Invocations = []sarif.Invocation{{
			ExecutionSuccessful: false,
			ExitCode:            ptr(input.ErrorCode()),
			ExitCodeDescription: ptr(input.ErrorCodeDescription()),
		}}
	}

	// marshal to json
	return json.Marshal(sarifReport)
}
